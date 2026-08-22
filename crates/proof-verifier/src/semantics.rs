#![allow(
    clippy::manual_let_else,
    clippy::needless_continue,
    clippy::option_option,
    clippy::single_match_else,
    clippy::too_many_lines,
    reason = "semantic verification keeps trust promotion adjacent to each fail-closed check"
)]

use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    ParsedCheckpoint,
    container::{LoadedArtifact, LoadedBundle, RequiredArtifact},
    crypto::{
        PublicSigner, domain_digest, parse_dsse_unverified, parse_public_signer, verify_dsse,
    },
    model::{
        ArtifactKind, CheckpointRequirement, Digest, DimensionStatus, EvidenceRole, HistoryScope,
        OpeningRequirement, Report, TrustPolicy, TrustedKey,
    },
    operation, schema,
    strict_json::canonical_bytes,
};

const AUTHORITY_PAYLOAD: &str = "application/vnd.proof.authority-record.v1+json";
const ROOT_TRANSITION_PAYLOAD: &str =
    "application/vnd.proof.workspace-authority-root-transition.v1+json";
const AUTHENTICATED_COMMAND_PAYLOAD: &str = "application/vnd.proof.authenticated-command.v1+json";
const IN_TOTO_PAYLOAD: &str = "application/vnd.in-toto+json";
const IN_TOTO_STATEMENT: &str = "https://in-toto.io/Statement/v1";
const MAX_AUTHORITY_PAYLOAD_BYTES: usize = 65_536;
const MAX_AUTHORITY_ENVELOPE_BYTES: usize = 98_304;
const MAX_COMMAND_PAYLOAD_BYTES: usize = 4_096;
const MAX_COMMAND_ENVELOPE_BYTES: usize = 16_384;

#[derive(Clone)]
struct VerifiedAuthorityRecord {
    sequence: u64,
    digest: Digest,
    value: Value,
    recorded_at: OffsetDateTime,
}

pub(crate) fn parse_timestamp(value: &str) -> Option<OffsetDateTime> {
    if !value.ends_with('Z') {
        return None;
    }
    let parsed = OffsetDateTime::parse(value, &Rfc3339).ok()?;
    (parsed.format(&Rfc3339).ok()?.as_str() == value).then_some(parsed)
}

pub(crate) fn verify_semantics(
    loaded: &LoadedBundle,
    trust: &TrustPolicy,
    checkpoint: Option<&ParsedCheckpoint>,
    report: &mut Report,
) {
    verify_public_wire_schemas(loaded, report);
    let records = verify_authority(loaded, trust, checkpoint, report);
    if records.is_empty() {
        return;
    }
    verify_commands(loaded, trust, &records, report);
    verify_localized_consequences(loaded, &records, report);
    verify_subject_opening(loaded, trust, &records, report);
    verify_release(loaded, trust, &records, report);
}

fn verify_public_wire_schemas(loaded: &LoadedBundle, report: &mut Report) {
    for (reference, artifact) in &loaded.artifacts {
        let api_version = string(&artifact.value, "api_version");
        let localized = matches!(
            api_version,
            Some(
                "proof.dev/content-resource-intent/v1"
                    | "proof.dev/localized-content-policy/v1"
                    | "proof.dev/context-pack/v2"
                    | "proof.dev/edit/v2"
                    | "proof.dev/edit-batch/v2"
                    | "proof.dev/changeset/v2"
                    | "proof.dev/validation-results/v2"
                    | "proof.dev/object-locale-revision/v1"
                    | "proof.dev/object-set/v2"
                    | "proof.dev/known-state/v2"
                    | "proof.dev/edition/v2"
                    | "proof.dev/edition-delta/v2"
                    | "proof.dev/release/v2"
                    | "proof.dev/release-proof-predicate/v2"
            )
        );
        if localized && !schema::localized_artifact(&artifact.value) {
            invalid(
                report,
                "canonical",
                "proof.verify.artifact.schema",
                Some(reference.digest),
                None,
            );
        }
    }
}

fn verify_authority(
    loaded: &LoadedBundle,
    trust: &TrustPolicy,
    checkpoint: Option<&ParsedCheckpoint>,
    report: &mut Report,
) -> Vec<VerifiedAuthorityRecord> {
    let mut records = Vec::new();
    let mut active = match parse_public_signer(
        &trust.authority.initial_root.key_id,
        &trust.authority.initial_root.public_key,
    ) {
        Ok(value) => value,
        Err(_) => {
            invalid(
                report,
                "authority_signatures",
                "proof.verify.authority.root",
                None,
                None,
            );
            return records;
        }
    };
    let mut seen_authority_key_ids = BTreeSet::from([active.key_id.clone()]);
    let mut seen_authority_public_keys = BTreeSet::from([active.public_key]);
    let release_signers = trust
        .release
        .trusted_signers
        .iter()
        .filter_map(|key| parse_public_signer(&key.key_id, &key.public_key).ok())
        .collect::<Vec<_>>();
    if let Some(cutoff) = trust.authority.compromise_cutoff
        && loaded.bundle.included_authority_head.sequence > cutoff.sequence
    {
        invalid(
            report,
            "authority_checkpoint",
            "proof.verify.authority.beyond_compromise_cutoff",
            Some(loaded.bundle.included_authority_head.record_digest),
            Some(loaded.bundle.included_authority_head.sequence),
        );
        return records;
    }
    let mut previous_digest = None;
    for entry in &loaded.bundle.authority_prefix {
        let Some(envelope) = loaded.artifacts.get(&entry.authority_envelope) else {
            incomplete(
                report,
                "authority_signatures",
                "proof.verify.authority.envelope_missing",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
            continue;
        };
        let peek = match parse_dsse_unverified(
            &envelope.bytes,
            trust.limits.max_json_depth as usize,
            MAX_AUTHORITY_ENVELOPE_BYTES,
            MAX_AUTHORITY_PAYLOAD_BYTES,
        ) {
            Ok(value) => value,
            Err(_) => {
                invalid(
                    report,
                    "authority_signatures",
                    "proof.verify.authority.envelope_invalid",
                    Some(entry.record_digest),
                    Some(entry.sequence),
                );
                continue;
            }
        };
        let api_version = string(&peek.payload, "api_version").unwrap_or_default();
        let transition = api_version == "proof.dev/workspace-authority-root-transition/v1";
        let mut signers = vec![active.clone()];
        let successor = if transition {
            let key_id = string(&peek.payload, "successor_authority_key_id");
            let public_key = string(&peek.payload, "successor_public_key");
            match (key_id, public_key) {
                (Some(key_id), Some(public_key)) => match parse_public_signer(key_id, public_key) {
                    Ok(value) => {
                        signers.push(value.clone());
                        Some(value)
                    }
                    Err(_) => None,
                },
                _ => None,
            }
        } else {
            None
        };
        if transition && successor.is_none() {
            invalid(
                report,
                "authority_signatures",
                "proof.verify.authority.rotation_key",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
            continue;
        }
        let payload_type = if transition {
            ROOT_TRANSITION_PAYLOAD
        } else {
            AUTHORITY_PAYLOAD
        };
        let verified = match verify_dsse(
            &envelope.bytes,
            ArtifactKind::AuthorityRecordEnvelopeV1,
            &[payload_type],
            &signers,
            trust.limits.max_json_depth as usize,
            MAX_AUTHORITY_ENVELOPE_BYTES,
            MAX_AUTHORITY_PAYLOAD_BYTES,
        ) {
            Ok(value) => value,
            Err(_) => {
                invalid(
                    report,
                    "authority_signatures",
                    "proof.verify.authority.signature",
                    Some(entry.record_digest),
                    Some(entry.sequence),
                );
                continue;
            }
        };
        let value = verified.payload;
        if !schema::authority_record(&value) || !authority_record_shape_is_valid(&value) {
            invalid(
                report,
                "authority_sequence",
                "proof.verify.authority.record_schema",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
            continue;
        }
        let actual_digest = domain_digest(ArtifactKind::AuthorityRecordV1, &verified.payload_bytes);
        let sequence = u64_field(&value, "authority_sequence");
        let workspace = string(&value, "workspace_id");
        let previous = optional_digest_field(&value, "previous_authority_record_digest");
        let record_time = record_time(&value);
        if actual_digest != entry.record_digest
            || sequence != Some(entry.sequence)
            || workspace != Some(loaded.bundle.workspace_id.as_str())
            || previous != Some(previous_digest)
            || record_time.is_none()
        {
            invalid(
                report,
                "authority_sequence",
                "proof.verify.authority.chain",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
            continue;
        }
        let record_time = record_time.unwrap_or(OffsetDateTime::UNIX_EPOCH);
        if !key_active_at(&trust.authority.initial_root, record_time, &active.key_id)
            && active.key_id == trust.authority.initial_root.key_id
        {
            invalid(
                report,
                "authority_signatures",
                "proof.verify.authority.root_time",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
        }
        if transition {
            if string(&value, "predecessor_authority_key_id") != Some(active.key_id.as_str())
                || string(&value, "successor_authority_key_id") == Some(active.key_id.as_str())
            {
                invalid(
                    report,
                    "authority_signatures",
                    "proof.verify.authority.rotation",
                    Some(entry.record_digest),
                    Some(entry.sequence),
                );
            } else if let Some(next) = successor {
                if successor_key_is_fresh(
                    &next,
                    &mut seen_authority_key_ids,
                    &mut seen_authority_public_keys,
                    &release_signers,
                ) {
                    active = next;
                } else {
                    invalid(
                        report,
                        "authority_signatures",
                        "proof.verify.authority.rotation_reuse",
                        Some(entry.record_digest),
                        Some(entry.sequence),
                    );
                }
            }
        } else if api_version == "proof.dev/authorization-decision/v2"
            && string(&value, "authority_key_id") != Some(active.key_id.as_str())
        {
            invalid(
                report,
                "authority_signatures",
                "proof.verify.authority.decision_key",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
        }
        previous_digest = Some(entry.record_digest);
        records.push(VerifiedAuthorityRecord {
            sequence: entry.sequence,
            digest: entry.record_digest,
            value,
            recorded_at: record_time,
        });
    }
    if records.len() == loaded.bundle.authority_prefix.len() {
        report.valid("authority_signatures");
        report.valid("authority_sequence");
    }
    verify_causal_authority_state(&records, trust, report);
    let target_sequence = records
        .iter()
        .find(|record| {
            record.digest == loaded.bundle.entrypoints.target_authorization_record_digest
        })
        .map(|record| record.sequence);
    if let Some(cutoff) = trust.authority.compromise_cutoff {
        let cutoff_matches = records.iter().any(|record| {
            record.sequence == cutoff.sequence && record.digest == cutoff.record_digest
        });
        if !cutoff_matches || target_sequence.is_none_or(|sequence| sequence > cutoff.sequence) {
            invalid(
                report,
                "authority_checkpoint",
                "proof.verify.authority.compromise_cutoff",
                None,
                None,
            );
        }
    }
    match checkpoint {
        Some(parsed) => {
            let value = &parsed.checkpoint;
            let head = loaded.bundle.included_authority_head;
            let last_time = records.last().map(|record| record.recorded_at);
            if value.workspace_id != loaded.bundle.workspace_id
                || value.authority_sequence != head.sequence
                || value.authority_record_digest != head.record_digest
                || value.active_authority_key_id != active.key_id
                || parse_timestamp(&value.observed_at)
                    .zip(last_time)
                    .is_none_or(|(observed, recorded)| observed < recorded)
            {
                invalid(
                    report,
                    "authority_checkpoint",
                    "proof.verify.checkpoint.mismatch",
                    None,
                    None,
                );
            } else {
                report.history_scope = HistoryScope::PinnedHead;
                report.valid("authority_checkpoint");
            }
        }
        None if trust.authority.checkpoint_requirement == CheckpointRequirement::Required => {
            incomplete(
                report,
                "authority_checkpoint",
                "proof.verify.checkpoint.required",
                None,
                None,
            );
        }
        None => {
            report.history_scope = HistoryScope::InternalPrefix;
            report.not_required("authority_checkpoint");
        }
    }
    report.verified_claims.authority_head = Some(loaded.bundle.included_authority_head);
    records
}

#[derive(Clone, Copy)]
struct PrincipalFact<'a> {
    kind: &'a str,
    enabled: bool,
    terminally_disabled: bool,
}

fn verify_causal_authority_state(
    records: &[VerifiedAuthorityRecord],
    trust: &TrustPolicy,
    report: &mut Report,
) {
    let mut principals = BTreeMap::<String, PrincipalFact<'_>>::new();
    let mut bindings = BTreeMap::<String, &VerifiedAuthorityRecord>::new();
    let mut binding_keys = BTreeSet::<String>::new();
    let mut binding_revocations = BTreeMap::<String, &VerifiedAuthorityRecord>::new();
    let mut delegations = BTreeMap::<String, &VerifiedAuthorityRecord>::new();
    let mut delegation_revocations = BTreeMap::<String, &VerifiedAuthorityRecord>::new();
    let release_key_ids = trust
        .release
        .trusted_signers
        .iter()
        .map(|key| key.key_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut valid = true;

    for record in records {
        let api = string(&record.value, "api_version").unwrap_or_default();
        let actor_is_enabled_human = |principal_id: Option<&str>| {
            principal_id
                .and_then(|principal_id| principals.get(principal_id))
                .is_some_and(|principal| principal.kind == "human" && principal.enabled)
        };
        let record_valid = match api {
            "proof.dev/principal-status/v1" => {
                let principal_id = string(&record.value, "principal_id");
                let kind = string(&record.value, "principal_type");
                let enabled = record.value.get("enabled").and_then(Value::as_bool);
                let recorder = string(&record.value, "recorded_by_principal_id");
                let bootstrap = principals.is_empty()
                    && principal_id == recorder
                    && kind == Some("human")
                    && enabled == Some(true);
                let administered = !principals.is_empty() && actor_is_enabled_human(recorder);
                let transition_valid = principal_id.zip(kind).zip(enabled).is_some_and(
                    |((principal_id, kind), enabled)| {
                        principals.get(principal_id).is_none_or(|previous| {
                            previous.kind == kind && !(previous.terminally_disabled && enabled)
                        })
                    },
                );
                if (bootstrap || administered) && transition_valid {
                    let principal_id = principal_id.unwrap_or_default();
                    let kind = kind.unwrap_or_default();
                    let enabled = enabled.unwrap_or(false);
                    let terminally_disabled = principals
                        .get(principal_id)
                        .is_some_and(|previous| previous.terminally_disabled)
                        || !enabled;
                    principals.insert(
                        principal_id.to_owned(),
                        PrincipalFact {
                            kind,
                            enabled,
                            terminally_disabled,
                        },
                    );
                    true
                } else {
                    false
                }
            }
            "proof.dev/principal-binding/v1" => {
                let binding_id = string(&record.value, "binding_id");
                let principal_id = string(&record.value, "principal_id");
                let issuer = string(&record.value, "issued_by_principal_id");
                let key_id = record
                    .value
                    .pointer("/authenticated_subject/subject")
                    .and_then(Value::as_str);
                let time_valid = string(&record.value, "issued_at")
                    .and_then(parse_timestamp)
                    .zip(string(&record.value, "not_before").and_then(parse_timestamp))
                    .zip(string(&record.value, "expires_at").and_then(parse_timestamp))
                    .is_some_and(|((issued, start), end)| issued <= start && start < end);
                let candidate = binding_id.zip(key_id).is_some_and(|(binding_id, key_id)| {
                    !bindings.contains_key(binding_id)
                        && !binding_keys.contains(key_id)
                        && key_id != trust.authority.initial_root.key_id
                        && !release_key_ids.contains(key_id)
                });
                let principal_valid = principal_id
                    .and_then(|principal_id| principals.get(principal_id))
                    .is_some_and(|principal| principal.kind == "agent" && principal.enabled);
                if actor_is_enabled_human(issuer) && principal_valid && candidate && time_valid {
                    bindings.insert(binding_id.unwrap_or_default().to_owned(), record);
                    binding_keys.insert(key_id.unwrap_or_default().to_owned());
                    true
                } else {
                    false
                }
            }
            "proof.dev/principal-binding-revocation/v1" => {
                let binding_id = string(&record.value, "binding_id");
                let actor = string(&record.value, "revoked_by_principal_id");
                let target = binding_id.and_then(|binding_id| bindings.get(binding_id).copied());
                let chronological = target
                    .zip(string(&record.value, "revoked_at").and_then(parse_timestamp))
                    .is_some_and(|(binding, revoked)| binding.recorded_at <= revoked);
                if actor_is_enabled_human(actor)
                    && target.is_some()
                    && chronological
                    && binding_id.is_some_and(|id| !binding_revocations.contains_key(id))
                {
                    binding_revocations.insert(binding_id.unwrap_or_default().to_owned(), record);
                    true
                } else {
                    false
                }
            }
            "proof.dev/delegation/v2" => {
                let delegation_id = string(&record.value, "delegation_id");
                let issuer = string(&record.value, "issuer_principal_id");
                let recipient = string(&record.value, "recipient_principal_id");
                let recipient_valid = recipient
                    .and_then(|recipient| principals.get(recipient))
                    .is_some_and(|principal| principal.kind == "agent" && principal.enabled);
                let time_valid = string(&record.value, "issued_at")
                    .and_then(parse_timestamp)
                    .zip(string(&record.value, "not_before").and_then(parse_timestamp))
                    .zip(string(&record.value, "expires_at").and_then(parse_timestamp))
                    .is_some_and(|((issued, start), end)| issued <= start && start < end);
                if actor_is_enabled_human(issuer)
                    && recipient_valid
                    && issuer != recipient
                    && time_valid
                    && delegation_id.is_some_and(|id| !delegations.contains_key(id))
                {
                    delegations.insert(delegation_id.unwrap_or_default().to_owned(), record);
                    true
                } else {
                    false
                }
            }
            "proof.dev/delegation-revocation/v1" => {
                let delegation_id = string(&record.value, "delegation_id");
                let actor = string(&record.value, "revoked_by_principal_id");
                let target =
                    delegation_id.and_then(|delegation_id| delegations.get(delegation_id).copied());
                let chronological = target
                    .zip(string(&record.value, "revoked_at").and_then(parse_timestamp))
                    .is_some_and(|(delegation, revoked)| delegation.recorded_at <= revoked);
                if actor_is_enabled_human(actor)
                    && target.is_some()
                    && chronological
                    && delegation_id.is_some_and(|id| !delegation_revocations.contains_key(id))
                {
                    delegation_revocations
                        .insert(delegation_id.unwrap_or_default().to_owned(), record);
                    true
                } else {
                    false
                }
            }
            "proof.dev/authorization-decision/v2" => decision_matches_causal_state(
                record,
                &principals,
                &bindings,
                &binding_revocations,
                &delegations,
                &delegation_revocations,
            ),
            "proof.dev/workspace-authority-root-transition/v1" => {
                actor_is_enabled_human(string(&record.value, "activated_by_principal_id"))
            }
            _ => false,
        };
        if !record_valid {
            valid = false;
            invalid(
                report,
                "authority_sequence",
                "proof.verify.authority.causal_state",
                Some(record.digest),
                Some(record.sequence),
            );
        }
    }
    if valid {
        report.valid("authority_sequence");
    }
}

fn decision_matches_causal_state(
    decision: &VerifiedAuthorityRecord,
    principals: &BTreeMap<String, PrincipalFact<'_>>,
    bindings: &BTreeMap<String, &VerifiedAuthorityRecord>,
    binding_revocations: &BTreeMap<String, &VerifiedAuthorityRecord>,
    delegations: &BTreeMap<String, &VerifiedAuthorityRecord>,
    delegation_revocations: &BTreeMap<String, &VerifiedAuthorityRecord>,
) -> bool {
    let evaluated = match string(&decision.value, "evaluated_at").and_then(parse_timestamp) {
        Some(value) => value,
        None => return false,
    };
    let requesting = string(&decision.value, "requesting_principal_id");
    let operating = string(&decision.value, "operating_principal_id");
    let requesting_fact = requesting.and_then(|id| principals.get(id));
    let operating_fact = operating.and_then(|id| principals.get(id));
    let claimed_requesting = decision
        .value
        .pointer("/principal_state/requesting_principal_enabled")
        .and_then(Value::as_bool);
    let claimed_operating = decision
        .value
        .pointer("/principal_state/operating_principal_enabled")
        .and_then(Value::as_bool);
    if requesting_fact.is_none_or(|fact| fact.kind != "human")
        || operating_fact.is_none_or(|fact| fact.kind != "agent")
        || claimed_requesting != requesting_fact.map(|fact| fact.enabled)
        || claimed_operating != operating_fact.map(|fact| fact.enabled)
    {
        return false;
    }

    let binding_id = decision
        .value
        .pointer("/binding/binding_id")
        .and_then(Value::as_str);
    let binding = binding_id.and_then(|id| bindings.get(id).copied());
    let actual_binding_revocation = binding_id.and_then(|id| binding_revocations.get(id).copied());
    let binding_pointer =
        optional_digest_path(&decision.value, &["binding", "revocation_record_digest"]);
    let binding_matches = binding.is_some_and(|binding| {
        digest_path(&decision.value, &["binding", "record_digest"]) == Some(binding.digest)
            && decision
                .value
                .pointer("/binding/authority_sequence")
                .and_then(Value::as_u64)
                == Some(binding.sequence)
            && string(&binding.value, "principal_id") == operating
    }) && binding_pointer
        == Some(actual_binding_revocation.map(|record| record.digest));
    if !binding_matches {
        return false;
    }

    let delegation_id = decision
        .value
        .pointer("/delegation/delegation_id")
        .and_then(Value::as_str);
    let delegation = delegation_id.and_then(|id| delegations.get(id).copied());
    let actual_delegation_revocation =
        delegation_id.and_then(|id| delegation_revocations.get(id).copied());
    let delegation_pointer =
        optional_digest_path(&decision.value, &["delegation", "revocation_record_digest"]);
    let resolution = decision
        .value
        .pointer("/delegation/resolution")
        .and_then(Value::as_str);
    let delegation_matches = match delegation {
        Some(delegation) => {
            resolution == Some("resolved")
                && digest_path(&decision.value, &["delegation", "record_digest"])
                    == Some(delegation.digest)
                && delegation_pointer
                    == Some(actual_delegation_revocation.map(|record| record.digest))
        }
        None => {
            resolution == Some("not_found_or_hidden")
                && decision
                    .value
                    .pointer("/delegation/record_digest")
                    .is_some_and(Value::is_null)
                && delegation_pointer == Some(None)
        }
    };
    if !delegation_matches {
        return false;
    }

    let binding_time_active = binding.is_some_and(|binding| {
        string(&binding.value, "not_before")
            .and_then(parse_timestamp)
            .zip(string(&binding.value, "expires_at").and_then(parse_timestamp))
            .is_some_and(|(start, end)| start <= evaluated && evaluated < end)
    });
    let mut expected_denial = if claimed_requesting != Some(true) || claimed_operating != Some(true)
    {
        Some("proof.authorization.principal_disabled")
    } else if !binding_time_active || actual_binding_revocation.is_some() {
        Some("proof.auth.binding_inactive")
    } else if delegation.is_none() {
        Some("proof.authorization.delegation_unavailable")
    } else {
        None
    };
    if expected_denial.is_none() {
        let delegation = delegation.unwrap();
        let start = string(&delegation.value, "not_before").and_then(parse_timestamp);
        let end = string(&delegation.value, "expires_at").and_then(parse_timestamp);
        let actor_mismatch = string(&delegation.value, "issuer_principal_id") != requesting
            || string(&delegation.value, "recipient_principal_id") != operating;
        let action_missing = delegation
            .value
            .get("actions")
            .and_then(Value::as_array)
            .zip(string(&decision.value, "requested_action"))
            .is_none_or(|(actions, requested)| {
                !actions
                    .iter()
                    .any(|action| action.as_str() == Some(requested))
            });
        let scope_exceeded = actor_mismatch
            || action_missing
            || !decision_scope_is_covered(decision, &delegation.value);
        let budget_exceeded = !decision_budget_is_covered(decision, &delegation.value);
        expected_denial = if actor_mismatch {
            Some("proof.authorization.scope_exceeded")
        } else if actual_delegation_revocation.is_some() {
            Some("proof.authorization.delegation_revoked")
        } else if start.is_some_and(|start| evaluated < start) {
            Some("proof.authorization.delegation_not_yet_valid")
        } else if end.is_none_or(|end| evaluated >= end) {
            Some("proof.authorization.delegation_expired")
        } else if scope_exceeded {
            Some("proof.authorization.scope_exceeded")
        } else if budget_exceeded {
            Some("proof.authorization.budget_exceeded")
        } else {
            None
        };
    }
    match expected_denial {
        Some(reason) => {
            string(&decision.value, "decision") == Some("deny")
                && string(&decision.value, "reason_code") == Some(reason)
        }
        None => {
            string(&decision.value, "decision") == Some("allow")
                && decision
                    .value
                    .get("reason_code")
                    .is_some_and(Value::is_null)
        }
    }
}

fn optional_digest_path(value: &Value, path: &[&str]) -> Option<Option<Digest>> {
    let mut current = value;
    for field in path {
        current = current.get(*field)?;
    }
    match current {
        Value::Null => Some(None),
        Value::String(raw) => Digest::parse(raw).map(Some),
        _ => None,
    }
}

fn decision_scope_is_covered(decision: &VerifiedAuthorityRecord, delegation: &Value) -> bool {
    [
        ("environment_ids", "/scope/environment_ids"),
        ("object_ids", "/scope/object_ids"),
        ("schema_ids", "/scope/schema_ids"),
        ("locales", "/scope/locales"),
    ]
    .into_iter()
    .all(|(requested, permitted)| {
        array_subset(
            decision
                .value
                .pointer(&format!("/requested_resources/{requested}")),
            delegation.pointer(permitted),
        )
    })
}

fn decision_budget_is_covered(decision: &VerifiedAuthorityRecord, delegation: &Value) -> bool {
    [
        "max_objects",
        "max_context_bytes",
        "max_edits_per_changeset",
    ]
    .into_iter()
    .all(|field| {
        decision
            .value
            .pointer(&format!("/effective_constraints/{field}"))
            .and_then(Value::as_u64)
            .zip(
                delegation
                    .pointer(&format!("/constraints/{field}"))
                    .and_then(Value::as_u64),
            )
            .is_some_and(|(requested, permitted)| requested <= permitted)
    })
}

fn successor_key_is_fresh(
    successor: &PublicSigner,
    seen_key_ids: &mut BTreeSet<String>,
    seen_public_keys: &mut BTreeSet<[u8; 32]>,
    release_signers: &[PublicSigner],
) -> bool {
    if seen_key_ids.contains(&successor.key_id)
        || seen_public_keys.contains(&successor.public_key)
        || release_signers.iter().any(|release| {
            release.key_id == successor.key_id || release.public_key == successor.public_key
        })
    {
        return false;
    }
    seen_key_ids.insert(successor.key_id.clone());
    seen_public_keys.insert(successor.public_key);
    true
}

#[expect(
    clippy::too_many_lines,
    reason = "the command proof joins its signature, binding, delegation, actor, and decision in one audit"
)]
fn verify_commands(
    loaded: &LoadedBundle,
    trust: &TrustPolicy,
    records: &[VerifiedAuthorityRecord],
    report: &mut Report,
) {
    let by_digest = records
        .iter()
        .map(|record| (record.digest, record))
        .collect::<BTreeMap<_, _>>();
    let mut presentations = BTreeSet::new();
    let mut decisions = 0_usize;
    for entry in &loaded.bundle.authority_prefix {
        let Some(record) = by_digest.get(&entry.record_digest).copied() else {
            continue;
        };
        let is_decision =
            string(&record.value, "api_version") == Some("proof.dev/authorization-decision/v2");
        if !is_decision {
            if entry.decision_companion.is_some() {
                invalid(
                    report,
                    "command_authentication",
                    "proof.verify.command.unexpected",
                    Some(entry.record_digest),
                    Some(entry.sequence),
                );
            }
            continue;
        }
        decisions += 1;
        let expected_audience = format!("proof://workspace/{}", loaded.bundle.workspace_id);
        let evaluated_head_sequence = record
            .value
            .pointer("/evaluated_authority_head/sequence")
            .and_then(Value::as_u64);
        let evaluated_head_digest = record
            .value
            .pointer("/evaluated_authority_head/record_digest")
            .and_then(Value::as_str)
            .and_then(Digest::parse);
        let previous = records
            .iter()
            .find(|candidate| candidate.sequence + 1 == record.sequence);
        let outcome = string(&record.value, "decision");
        let reason = record.value.get("reason_code");
        let decision_shape = string(&record.value, "audience") == Some(expected_audience.as_str())
            && record.value.pointer("/requested_resources/workspace_ids")
                == Some(&Value::Array(vec![Value::String(
                    loaded.bundle.workspace_id.clone(),
                )]))
            && record
                .value
                .get("presentation_consumed")
                .and_then(Value::as_bool)
                == Some(true)
            && evaluated_head_sequence == Some(record.sequence.saturating_sub(1))
            && evaluated_head_digest == previous.map(|candidate| candidate.digest)
            && digest_field(&record.value, "previous_authority_record_digest")
                == evaluated_head_digest
            && matches!(
                (outcome, reason),
                (Some("allow"), Some(Value::Null)) | (Some("deny"), Some(Value::String(_)))
            );
        if !decision_shape {
            invalid(
                report,
                "policy",
                "proof.verify.decision.shape",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
        }
        let Some(companion) = entry.decision_companion else {
            incomplete(
                report,
                "command_authentication",
                "proof.verify.command.missing",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
            continue;
        };
        let input = match loaded.required_artifact(&companion.command_input) {
            RequiredArtifact::Available(input) => input,
            RequiredArtifact::MissingRequiredExternal => {
                incomplete(
                    report,
                    "command_authentication",
                    "proof.verify.command.input_missing",
                    Some(entry.record_digest),
                    Some(entry.sequence),
                );
                continue;
            }
            RequiredArtifact::InvalidOrAbsent => {
                invalid(
                    report,
                    "command_authentication",
                    "proof.verify.command.input_missing",
                    Some(entry.record_digest),
                    Some(entry.sequence),
                );
                continue;
            }
        };
        let Some(envelope) = loaded
            .artifacts
            .get(&companion.authenticated_command_envelope)
        else {
            incomplete(
                report,
                "command_authentication",
                "proof.verify.command.envelope_missing",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
            continue;
        };
        let Some(actor) = loaded.artifacts.get(&companion.actor_context_evidence) else {
            incomplete(
                report,
                "principal_binding",
                "proof.verify.actor.missing",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
            continue;
        };
        let binding_digest = digest_path(&record.value, &["binding", "record_digest"]);
        let binding = binding_digest.and_then(|digest| by_digest.get(&digest).copied());
        let Some(binding) = binding else {
            invalid(
                report,
                "principal_binding",
                "proof.verify.binding.missing",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
            continue;
        };
        if string(&binding.value, "api_version") != Some("proof.dev/principal-binding/v1") {
            invalid(
                report,
                "principal_binding",
                "proof.verify.binding.kind",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
            continue;
        }
        let key_id = binding
            .value
            .pointer("/authenticated_subject/subject")
            .and_then(Value::as_str);
        let public_key = string(&binding.value, "public_key");
        let signer = key_id
            .zip(public_key)
            .and_then(|(key_id, public_key)| parse_public_signer(key_id, public_key).ok());
        let Some(signer) = signer else {
            invalid(
                report,
                "principal_binding",
                "proof.verify.binding.key",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
            continue;
        };
        let verified = verify_dsse(
            &envelope.bytes,
            ArtifactKind::AuthenticatedCommandEnvelopeV1,
            &[AUTHENTICATED_COMMAND_PAYLOAD],
            &[signer],
            trust.limits.max_json_depth as usize,
            MAX_COMMAND_ENVELOPE_BYTES,
            MAX_COMMAND_PAYLOAD_BYTES,
        );
        let Ok(verified) = verified else {
            invalid(
                report,
                "command_authentication",
                "proof.verify.command.signature",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
            continue;
        };
        let command_digest = companion.command_input.digest;
        let presentation = string(&verified.payload, "presentation_id");
        let evaluated = string(&record.value, "evaluated_at").and_then(parse_timestamp);
        let issued = string(&verified.payload, "issued_at").and_then(parse_timestamp);
        let expires = string(&verified.payload, "expires_at").and_then(parse_timestamp);
        let authenticated = string(&actor.value, "authenticated_at").and_then(parse_timestamp);
        let actor_contains_raw_uid = contains_raw_uid(&actor.value);
        let command_shape = schema::command_input(&input.value)
            && schema::authenticated_command(&verified.payload)
            && schema::actor_evidence(&actor.value)
            && object_keys_exact(
                &input.value,
                &[
                    "api_version",
                    "delegation_id",
                    "idempotency_key",
                    "normalized_input",
                    "operating_principal_id",
                    "operation",
                    "requesting_principal_id",
                    "workspace_id",
                ],
            )
            && object_keys_exact(
                &verified.payload,
                &[
                    "api_version",
                    "audience",
                    "binding_id",
                    "command_digest",
                    "delegation_id",
                    "expires_at",
                    "idempotency_key",
                    "issued_at",
                    "operating_principal_id",
                    "operation",
                    "presentation_id",
                    "requesting_principal_id",
                    "workspace_id",
                ],
            )
            && object_keys_exact(
                &actor.value,
                &[
                    "api_version",
                    "audience",
                    "authenticated_at",
                    "authentication_profile",
                    "binding_id",
                    "command_digest",
                    "command_envelope_digest",
                    "delegation_id",
                    "operating_principal_id",
                    "operating_subject",
                    "operation",
                    "presentation_id",
                    "requesting_principal_id",
                    "requesting_subject_commitment",
                    "workspace_id",
                ],
            );
        let common_fields = [
            "workspace_id",
            "operation",
            "requesting_principal_id",
            "operating_principal_id",
        ];
        let outer_matches = common_fields.iter().all(|field| {
            input.value.get(*field) == verified.payload.get(*field)
                && input.value.get(*field) == record.value.get(*field)
                && input.value.get(*field) == actor.value.get(*field)
        });
        let cross_links = command_shape
            && outer_matches
            && string(&input.value, "api_version") == Some("proof.dev/command-input/v1")
            && string(&verified.payload, "api_version")
                == Some("proof.dev/authenticated-command/v1")
            && string(&actor.value, "api_version")
                == Some("proof.dev/authenticated-actor-context-evidence/v1")
            && string(&actor.value, "authentication_profile")
                == Some("proof.local/authentication/human-agent/v1")
            && string(&verified.payload, "audience") == Some(expected_audience.as_str())
            && string(&actor.value, "audience") == Some(expected_audience.as_str())
            && input.value.get("delegation_id") == verified.payload.get("delegation_id")
            && input.value.get("delegation_id")
                == record.value.pointer("/delegation/delegation_id")
            && input.value.get("delegation_id") == actor.value.get("delegation_id")
            && input.value.get("idempotency_key") == verified.payload.get("idempotency_key")
            && verified.payload.get("binding_id") == record.value.pointer("/binding/binding_id")
            && verified.payload.get("binding_id") == actor.value.get("binding_id")
            && actor.value.get("operating_subject") == binding.value.get("authenticated_subject")
            && digest_field(&actor.value, "requesting_subject_commitment")
                == digest_field(&record.value, "requesting_subject_commitment")
            && authenticated.is_some()
            && digest_field(&record.value, "command_digest") == Some(command_digest)
            && digest_field(&record.value, "command_envelope_digest")
                == Some(companion.authenticated_command_envelope.digest)
            && digest_field(&record.value, "actor_context_digest")
                == Some(companion.actor_context_evidence.digest)
            && digest_field(&verified.payload, "command_digest") == Some(command_digest)
            && digest_field(&actor.value, "command_digest") == Some(command_digest)
            && digest_field(&actor.value, "command_envelope_digest")
                == Some(companion.authenticated_command_envelope.digest)
            && string(&verified.payload, "workspace_id")
                == Some(loaded.bundle.workspace_id.as_str())
            && string(&input.value, "workspace_id") == Some(loaded.bundle.workspace_id.as_str())
            && presentation == string(&record.value, "presentation_id")
            && presentation.is_some_and(|value| presentations.insert(value.to_owned()))
            && evaluated
                .zip(issued)
                .zip(expires)
                .is_some_and(|((evaluated, issued), expires)| {
                    issued <= evaluated
                        && evaluated < expires
                        && issued < expires
                        && (expires - issued).whole_seconds() <= 300
                });
        if !cross_links || actor_contains_raw_uid {
            invalid(
                report,
                "command_authentication",
                "proof.verify.command.cross_link",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
        }
        let projection_valid = digest_path(&record.value, &["delegation", "record_digest"])
            .and_then(|digest| by_digest.get(&digest).copied())
            .and_then(|delegation| {
                operation::validate_command_and_projection(
                    loaded,
                    &input.value,
                    &record.value,
                    &delegation.value,
                )
            })
            .is_some();
        if !projection_valid {
            invalid(
                report,
                "policy",
                "proof.verify.command.operation_projection",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
        }
        let binding_identity = string(&binding.value, "binding_id")
            == record
                .value
                .pointer("/binding/binding_id")
                .and_then(Value::as_str)
            && u64_field(&binding.value, "authority_sequence")
                == record
                    .value
                    .pointer("/binding/authority_sequence")
                    .and_then(Value::as_u64)
            && Some(binding.sequence)
                == record
                    .value
                    .pointer("/binding/authority_sequence")
                    .and_then(Value::as_u64)
            && evaluated_head_sequence.is_some_and(|head| binding.sequence <= head)
            && string(&binding.value, "principal_id")
                == string(&record.value, "operating_principal_id")
            && string(&binding.value, "principal_type") == Some("agent")
            && string(&binding.value, "algorithm") == Some("ed25519")
            && string(&binding.value, "key_usage") == Some("authenticated-command")
            && string(&binding.value, "audience") == Some(expected_audience.as_str());
        let binding_time_active = evaluated
            .zip(string(&binding.value, "not_before").and_then(parse_timestamp))
            .zip(string(&binding.value, "expires_at").and_then(parse_timestamp))
            .is_some_and(|((evaluated, start), end)| start <= evaluated && evaluated < end);
        let binding_revocation = decision_revocation_record(
            record.value.pointer("/binding/revocation_record_digest"),
            &by_digest,
            "proof.dev/principal-binding-revocation/v1",
            "binding_id",
            string(&binding.value, "binding_id"),
            evaluated_head_sequence,
            evaluated,
        );
        let allow = string(&record.value, "decision") == Some("allow");
        if !binding_identity
            || (allow && (!binding_time_active || binding_revocation != Some(false)))
            || (!allow && binding_revocation.is_none())
        {
            invalid(
                report,
                "principal_binding",
                "proof.verify.binding.inactive",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
        }
        verify_principal_state(record, &by_digest, report);
        verify_delegation(record, &by_digest, report);
        let accepted = trust
            .authority
            .accepted_policy_bundles
            .iter()
            .any(|policy| {
                string(&record.value, "policy_profile") == Some(policy.policy_profile.as_str())
                    && digest_field(&record.value, "policy_bundle_digest")
                        == Some(policy.policy_bundle_digest)
            });
        if !accepted {
            invalid(
                report,
                "policy",
                "proof.verify.authority.policy_untrusted",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
        }
        if digest_field(&record.value, "requesting_subject_commitment").is_none() {
            invalid(
                report,
                "subject_commitment",
                "proof.verify.subject.commitment_missing",
                Some(entry.record_digest),
                Some(entry.sequence),
            );
        }
    }
    if decisions == 0 {
        invalid(
            report,
            "command_authentication",
            "proof.verify.command.no_decisions",
            None,
            None,
        );
        return;
    }
    for dimension in [
        "command_authentication",
        "principal_binding",
        "delegation",
        "policy",
        "subject_commitment",
    ] {
        report.valid(dimension);
    }
}

fn verify_delegation(
    decision: &VerifiedAuthorityRecord,
    records: &BTreeMap<Digest, &VerifiedAuthorityRecord>,
    report: &mut Report,
) {
    let resolution = decision
        .value
        .pointer("/delegation/resolution")
        .and_then(Value::as_str);
    let outcome = string(&decision.value, "decision");
    let reason = string(&decision.value, "reason_code");
    if resolution == Some("not_found_or_hidden") {
        let hidden_deny = outcome == Some("deny")
            && reason == Some("proof.authorization.delegation_unavailable")
            && decision
                .value
                .pointer("/delegation/record_digest")
                .is_some_and(Value::is_null)
            && decision
                .value
                .pointer("/delegation/revocation_record_digest")
                .is_some_and(Value::is_null);
        if !hidden_deny {
            invalid(
                report,
                "delegation",
                "proof.verify.delegation.hidden",
                Some(decision.digest),
                Some(decision.sequence),
            );
        }
        return;
    }
    let digest = digest_path(&decision.value, &["delegation", "record_digest"]);
    let delegation = digest.and_then(|digest| records.get(&digest).copied());
    let evaluated = string(&decision.value, "evaluated_at").and_then(parse_timestamp);
    let causal_head = decision
        .value
        .pointer("/evaluated_authority_head/sequence")
        .and_then(Value::as_u64);
    let valid = delegation.is_some_and(|delegation| {
        let time_active = evaluated
            .zip(string(&delegation.value, "not_before").and_then(parse_timestamp))
            .zip(string(&delegation.value, "expires_at").and_then(parse_timestamp))
            .is_some_and(|((evaluated, start), end)| start <= evaluated && evaluated < end);
        let revocation = decision_revocation_record(
            decision
                .value
                .pointer("/delegation/revocation_record_digest"),
            records,
            "proof.dev/delegation-revocation/v1",
            "delegation_id",
            string(&delegation.value, "delegation_id"),
            causal_head,
            evaluated,
        );
        let action_allowed = delegation
            .value
            .get("actions")
            .and_then(Value::as_array)
            .zip(string(&decision.value, "requested_action"))
            .is_some_and(|(actions, requested)| {
                actions
                    .iter()
                    .any(|action| action.as_str() == Some(requested))
            });
        let scope_allowed = [
            ("environment_ids", "/scope/environment_ids"),
            ("object_ids", "/scope/object_ids"),
            ("schema_ids", "/scope/schema_ids"),
            ("locales", "/scope/locales"),
        ]
        .into_iter()
        .all(|(requested, delegated)| {
            array_subset(
                decision
                    .value
                    .pointer(&format!("/requested_resources/{requested}")),
                delegation.value.pointer(delegated),
            )
        });
        let budgets_allowed = [
            "max_objects",
            "max_context_bytes",
            "max_edits_per_changeset",
        ]
        .into_iter()
        .all(|field| {
            decision
                .value
                .pointer(&format!("/effective_constraints/{field}"))
                .and_then(Value::as_u64)
                .zip(
                    delegation
                        .value
                        .pointer(&format!("/constraints/{field}"))
                        .and_then(Value::as_u64),
                )
                .is_some_and(|(effective, delegated)| effective <= delegated)
        });
        let causal_outcome = match outcome {
            Some("allow") => time_active && revocation == Some(false),
            Some("deny") => match reason {
                Some("proof.authorization.delegation_revoked") => revocation == Some(true),
                Some("proof.authorization.delegation_expired") => evaluated
                    .zip(string(&delegation.value, "expires_at").and_then(parse_timestamp))
                    .is_some_and(|(evaluated, end)| evaluated >= end),
                Some("proof.authorization.delegation_not_yet_valid") => evaluated
                    .zip(string(&delegation.value, "not_before").and_then(parse_timestamp))
                    .is_some_and(|(evaluated, start)| evaluated < start),
                _ => revocation.is_some(),
            },
            _ => false,
        };
        string(&delegation.value, "api_version") == Some("proof.dev/delegation/v2")
            && causal_head.is_some_and(|head| delegation.sequence <= head)
            && evaluated.is_some_and(|evaluated| delegation.recorded_at <= evaluated)
            && string(&delegation.value, "delegation_profile")
                == Some("proof.local/authority/direct/v1")
            && string(&delegation.value, "issuer_principal_id")
                == string(&decision.value, "requesting_principal_id")
            && string(&delegation.value, "recipient_principal_id")
                == string(&decision.value, "operating_principal_id")
            && string(&delegation.value, "delegation_id")
                == decision
                    .value
                    .pointer("/delegation/delegation_id")
                    .and_then(Value::as_str)
            && delegation.value.get("parent_delegation_id").is_none()
            && delegation
                .value
                .pointer("/constraints/allow_subdelegation")
                .and_then(Value::as_bool)
                == Some(false)
            && action_allowed
            && scope_allowed
            && budgets_allowed
            && causal_outcome
    });
    if !valid {
        invalid(
            report,
            "delegation",
            "proof.verify.delegation.invalid",
            Some(decision.digest),
            Some(decision.sequence),
        );
    }
}

fn verify_principal_state(
    decision: &VerifiedAuthorityRecord,
    records: &BTreeMap<Digest, &VerifiedAuthorityRecord>,
    report: &mut Report,
) {
    let head = decision
        .value
        .pointer("/evaluated_authority_head/sequence")
        .and_then(Value::as_u64);
    let evaluated = string(&decision.value, "evaluated_at").and_then(parse_timestamp);
    let requesting = string(&decision.value, "requesting_principal_id");
    let operating = string(&decision.value, "operating_principal_id");
    let requesting_status = principal_status_at(records, requesting, head, evaluated);
    let operating_status = principal_status_at(records, operating, head, evaluated);
    let claimed_requesting = decision
        .value
        .pointer("/principal_state/requesting_principal_enabled")
        .and_then(Value::as_bool);
    let claimed_operating = decision
        .value
        .pointer("/principal_state/operating_principal_enabled")
        .and_then(Value::as_bool);
    let status_matches = requesting_status.zip(operating_status).is_some_and(
        |(requesting_status, operating_status)| {
            string(&requesting_status.value, "principal_type") == Some("human")
                && string(&operating_status.value, "principal_type") == Some("agent")
                && requesting_status
                    .value
                    .get("enabled")
                    .and_then(Value::as_bool)
                    == claimed_requesting
                && operating_status
                    .value
                    .get("enabled")
                    .and_then(Value::as_bool)
                    == claimed_operating
        },
    );
    let allow = string(&decision.value, "decision") == Some("allow");
    if !status_matches
        || (allow && (claimed_requesting != Some(true) || claimed_operating != Some(true)))
    {
        invalid(
            report,
            "principal_binding",
            "proof.verify.principal.state",
            Some(decision.digest),
            Some(decision.sequence),
        );
    }
}

fn principal_status_at<'a>(
    records: &'a BTreeMap<Digest, &VerifiedAuthorityRecord>,
    principal_id: Option<&str>,
    head: Option<u64>,
    evaluated: Option<OffsetDateTime>,
) -> Option<&'a VerifiedAuthorityRecord> {
    records
        .values()
        .copied()
        .filter(|record| {
            record.sequence <= head.unwrap_or(0)
                && evaluated.is_some_and(|evaluated| record.recorded_at <= evaluated)
                && string(&record.value, "api_version") == Some("proof.dev/principal-status/v1")
                && string(&record.value, "principal_id") == principal_id
        })
        .max_by_key(|record| record.sequence)
}

fn decision_revocation_record(
    value: Option<&Value>,
    records: &BTreeMap<Digest, &VerifiedAuthorityRecord>,
    api_version: &str,
    identity_field: &str,
    expected_identity: Option<&str>,
    causal_head: Option<u64>,
    evaluated: Option<OffsetDateTime>,
) -> Option<bool> {
    match value {
        Some(Value::Null) => Some(false),
        Some(Value::String(raw)) => {
            let digest = Digest::parse(raw)?;
            let record = records.get(&digest).copied()?;
            (string(&record.value, "api_version") == Some(api_version)
                && string(&record.value, identity_field) == expected_identity)
                .then_some(record)?;
            (record.sequence <= causal_head? && record.recorded_at <= evaluated?).then_some(true)
        }
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ApplicationOwnership {
    idempotency_kind: String,
    operation_name: String,
    operation_version: String,
    command_digest: Digest,
    result_digest: Digest,
    effect_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ApplicationLedgerEntry {
    ownership: ApplicationOwnership,
    first_sequence: u64,
    first_decision_digest: Digest,
    first_consequence_digest: Digest,
}

#[expect(
    clippy::too_many_lines,
    reason = "localized consequence verification reproduces the exact signed composite and global key ledger"
)]
fn verify_localized_consequences(
    loaded: &LoadedBundle,
    records: &[VerifiedAuthorityRecord],
    report: &mut Report,
) {
    let records = records
        .iter()
        .map(|record| (record.digest, record))
        .collect::<BTreeMap<_, _>>();
    let mut keys = BTreeMap::<String, ApplicationLedgerEntry>::new();
    let mut localized = 0_usize;
    for entry in &loaded.bundle.authority_prefix {
        let Some(record) = records.get(&entry.record_digest).copied() else {
            continue;
        };
        if string(&record.value, "api_version") != Some("proof.dev/authorization-decision/v2") {
            continue;
        }
        let Some(companion) = entry.decision_companion else {
            continue;
        };
        let commitment = record.value.get("localized_consequence_commitment");
        let decision = string(&record.value, "decision");
        match (decision, commitment) {
            (Some("deny"), None) => {
                if companion.result.is_some()
                    || companion.localized_consequence.is_some()
                    || companion.application_effect.is_some()
                {
                    invalid(
                        report,
                        "localized_consequence",
                        "proof.verify.consequence.deny_has_effect",
                        Some(record.digest),
                        Some(record.sequence),
                    );
                }
                continue;
            }
            (Some("allow"), None) => {
                if companion.result.is_some()
                    || companion.localized_consequence.is_some()
                    || companion.application_effect.is_some()
                {
                    invalid(
                        report,
                        "localized_consequence",
                        "proof.verify.consequence.nonlocalized_has_effect",
                        Some(record.digest),
                        Some(record.sequence),
                    );
                }
                continue;
            }
            (Some("allow"), Some(commitment)) => {
                localized += 1;
                let refs = companion
                    .result
                    .zip(companion.localized_consequence)
                    .zip(companion.application_effect);
                let Some(((result_ref, consequence_ref), effect_ref)) = refs else {
                    incomplete(
                        report,
                        "localized_consequence",
                        "proof.verify.consequence.missing",
                        Some(record.digest),
                        Some(record.sequence),
                    );
                    continue;
                };
                let values = loaded
                    .artifacts
                    .get(&result_ref)
                    .zip(loaded.artifacts.get(&consequence_ref))
                    .zip(loaded.artifacts.get(&effect_ref));
                let Some(((result, consequence), effect)) = values else {
                    incomplete(
                        report,
                        "localized_consequence",
                        "proof.verify.consequence.artifact_missing",
                        Some(record.digest),
                        Some(record.sequence),
                    );
                    continue;
                };
                let evidence = &consequence.value;
                let input = match loaded.required_artifact(&companion.command_input) {
                    RequiredArtifact::Available(input) => input,
                    RequiredArtifact::MissingRequiredExternal => {
                        incomplete(
                            report,
                            "localized_consequence",
                            "proof.verify.consequence.artifact_missing",
                            Some(companion.command_input.digest),
                            Some(record.sequence),
                        );
                        continue;
                    }
                    RequiredArtifact::InvalidOrAbsent => {
                        invalid(
                            report,
                            "localized_consequence",
                            "proof.verify.consequence.cross_link",
                            Some(companion.command_input.digest),
                            Some(record.sequence),
                        );
                        continue;
                    }
                };
                let result_digest = digest_path(evidence, &["result", "digest"]);
                let effect_digest = digest_field(evidence, "application_effect_digest");
                let consequence_digest = digest_field(evidence, "application_consequence_digest");
                let selectors_match = evidence.pointer("/selectors/changeset_ids")
                    == record.value.pointer("/requested_resources/changeset_ids")
                    && evidence.pointer("/selectors/edition_ids")
                        == record.value.pointer("/requested_resources/edition_ids")
                    && evidence.pointer("/selectors/release_ids")
                        == record.value.pointer("/requested_resources/release_ids");
                let operation_name = evidence.pointer("/operation/name").and_then(Value::as_str);
                let result_kind = evidence.pointer("/result/kind").and_then(Value::as_str);
                let result_contract = evidence.pointer("/result/contract").and_then(Value::as_str);
                let operation_version = evidence
                    .pointer("/operation/version")
                    .and_then(Value::as_str);
                let spec = evidence
                    .get("operation")
                    .and_then(operation::resolve)
                    .filter(|spec| spec.output.is_some());
                let schema_matches = spec.is_some_and(|spec| {
                    let expected_contract =
                        operation_output_contract(Some(spec.name), Some(spec.version));
                    string(evidence, "operation_output_schema") == expected_contract
                        && match result_kind {
                            Some("success") => {
                                result_contract == expected_contract
                                    && spec.output.is_some_and(|definition| {
                                        schema::localized_operation(definition, &result.value)
                                    })
                            }
                            Some("failure") => {
                                result_contract
                                    == Some("proof.dev/result/localized-operation-problem/v1")
                                    && localized_problem_is_exact(&result.value)
                            }
                            _ => false,
                        }
                });
                let effect_checks = spec.map(|spec| {
                    let effect_exact = localized_effect_is_exact(
                        loaded,
                        spec,
                        input,
                        &record.value,
                        result_kind,
                        result_ref,
                        &result.value,
                        effect_ref,
                        &effect.value,
                    );
                    let closure = localized_closure_is_exact(
                        loaded,
                        &records,
                        spec,
                        input,
                        &record.value,
                        evidence,
                        result_kind,
                        &effect.value,
                    );
                    let idempotency = application_idempotency_is_exact(
                        loaded,
                        spec,
                        input,
                        &record.value,
                        evidence,
                        result_kind,
                    );
                    let timestamp = semantic_timestamp_is_exact(spec, input, evidence);
                    (effect_exact, closure, idempotency, timestamp)
                });
                let effect_matches =
                    effect_checks.is_some_and(|(effect, closure, idempotency, timestamp)| {
                        effect && closure && idempotency && timestamp
                    });
                let target_release_matches = if record.digest
                    == loaded.bundle.entrypoints.target_authorization_record_digest
                {
                    operation_name == Some("release.create")
                        && effect_ref == loaded.bundle.entrypoints.target_release_manifest
                        && effect.value
                            == loaded
                                .artifacts
                                .get(&loaded.bundle.entrypoints.target_release_manifest)
                                .map_or(Value::Null, |artifact| artifact.value.clone())
                        && result.value.get("release_manifest") == Some(&effect.value)
                        && digest_field(&result.value, "release_digest") == Some(effect_ref.digest)
                        && result.value.get("release_id") == effect.value.get("release_id")
                        && digest_field(&result.value, "proof_envelope_digest")
                            == Some(
                                loaded
                                    .bundle
                                    .entrypoints
                                    .target_release_proof_envelope
                                    .digest,
                            )
                } else {
                    true
                };
                let cross_linked = string(evidence, "api_version")
                    == Some("proof.dev/authenticated-localized-consequence/v1")
                    && artifact_has_role(
                        loaded,
                        EvidenceRole::LocalizedConsequence,
                        consequence_ref,
                    )
                    && digest_field(evidence, "authorization_decision_digest")
                        == Some(record.digest)
                    && digest_field(evidence, "command_digest")
                        == digest_field(&record.value, "command_digest")
                    && string(evidence, "presentation_id")
                        == string(&record.value, "presentation_id")
                    && string(evidence, "workspace_id") == string(&record.value, "workspace_id")
                    && string(evidence, "requesting_principal_id")
                        == string(&record.value, "requesting_principal_id")
                    && string(evidence, "operating_principal_id")
                        == string(&record.value, "operating_principal_id")
                    && string(evidence, "delegation_id")
                        == record
                            .value
                            .pointer("/delegation/delegation_id")
                            .and_then(Value::as_str)
                    && evidence.get("operation") == record.value.get("operation")
                    && selectors_match
                    && schema_matches
                    && effect_matches
                    && target_release_matches
                    && result_digest == Some(result_ref.digest)
                    && effect_digest == Some(effect_ref.digest)
                    && result_ref.artifact_kind == ArtifactKind::OperationEffectV1
                    && object_keys_exact(
                        evidence,
                        &[
                            "api_version",
                            "application_consequence_digest",
                            "application_effect_digest",
                            "application_idempotency",
                            "authorization_decision_digest",
                            "closure",
                            "command_digest",
                            "delegation_id",
                            "operating_principal_id",
                            "operation",
                            "operation_output_schema",
                            "presentation_id",
                            "requesting_principal_id",
                            "result",
                            "selectors",
                            "semantic_timestamp",
                            "workspace_id",
                        ],
                    )
                    && evidence
                        .get("operation")
                        .is_some_and(|value| object_keys_exact(value, &["name", "version"]))
                    && evidence.get("result").is_some_and(|value| {
                        object_keys_exact(value, &["contract", "digest", "kind"])
                    })
                    && evidence.get("selectors").is_some_and(|value| {
                        object_keys_exact(value, &["changeset_ids", "edition_ids", "release_ids"])
                    })
                    && (consequence_ref == loaded.bundle.entrypoints.target_localized_consequence
                        || record.digest
                            != loaded.bundle.entrypoints.target_authorization_record_digest);
                let composite = json!({
                    "api_version": "proof.dev/authenticated-localized-consequence-commitment/v1",
                    "application_effect_digest": evidence.get("application_effect_digest"),
                    "application_idempotency": evidence.get("application_idempotency"),
                    "closure": evidence.get("closure"),
                    "command_digest": evidence.get("command_digest"),
                    "delegation_id": evidence.get("delegation_id"),
                    "operating_principal_id": evidence.get("operating_principal_id"),
                    "operation": evidence.get("operation"),
                    "requesting_principal_id": evidence.get("requesting_principal_id"),
                    "result": evidence.get("result"),
                    "selectors": evidence.get("selectors"),
                    "semantic_timestamp": evidence.get("semantic_timestamp"),
                    "workspace_id": evidence.get("workspace_id"),
                });
                let computed = canonical_bytes(&composite)
                    .ok()
                    .map(|bytes| domain_digest(ArtifactKind::OperationEffectV1, &bytes));
                if !cross_linked
                    || computed != consequence_digest
                    || digest_path(commitment, &["result_digest"]) != result_digest
                    || digest_path(commitment, &["application_consequence_digest"])
                        != consequence_digest
                    || string(commitment, "result_kind")
                        != evidence.pointer("/result/kind").and_then(Value::as_str)
                    || string(commitment, "result_contract") != result_contract
                    || result.value.is_null()
                    || !object_keys_exact(
                        commitment,
                        &[
                            "application_consequence_digest",
                            "result_contract",
                            "result_digest",
                            "result_kind",
                        ],
                    )
                {
                    invalid(
                        report,
                        "localized_consequence",
                        "proof.verify.consequence.cross_link",
                        Some(record.digest),
                        Some(record.sequence),
                    );
                    continue;
                }
                let key = evidence
                    .pointer("/application_idempotency/key")
                    .and_then(Value::as_str);
                if result_kind == Some("failure") {
                    if effect_digest != result_digest {
                        invalid(
                            report,
                            "application_key_history",
                            "proof.verify.application.failure_reserved",
                            Some(record.digest),
                            Some(record.sequence),
                        );
                    }
                } else if let Some(key) = key {
                    let ownership = ApplicationOwnership {
                        idempotency_kind: evidence
                            .pointer("/application_idempotency/kind")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        operation_name: operation_name.unwrap_or_default().to_owned(),
                        operation_version: operation_version.unwrap_or_default().to_owned(),
                        command_digest: digest_field(evidence, "command_digest")
                            .unwrap_or(record.digest),
                        result_digest: result_ref.digest,
                        effect_digest: effect_ref.digest,
                    };
                    match keys.get(key) {
                        Some(existing) if existing.ownership != ownership => invalid(
                            report,
                            "application_key_history",
                            "proof.verify.application.key_reused",
                            Some(record.digest),
                            Some(record.sequence),
                        ),
                        Some(existing)
                            if record.digest
                                == loaded.bundle.entrypoints.target_authorization_record_digest
                                && (existing.first_decision_digest != record.digest
                                    || existing.first_sequence != record.sequence
                                    || consequence_digest
                                        != Some(existing.first_consequence_digest)) =>
                        {
                            invalid(
                                report,
                                "application_key_history",
                                "proof.verify.application.entrypoint_not_first",
                                Some(record.digest),
                                Some(record.sequence),
                            );
                        }
                        Some(_) => {}
                        None => {
                            let Some(first_consequence_digest) = consequence_digest else {
                                continue;
                            };
                            keys.insert(
                                key.to_owned(),
                                ApplicationLedgerEntry {
                                    ownership,
                                    first_sequence: record.sequence,
                                    first_decision_digest: record.digest,
                                    first_consequence_digest,
                                },
                            );
                        }
                    }
                }
                if string(
                    evidence.pointer("/operation").unwrap_or(&Value::Null),
                    "name",
                ) == Some("release.create")
                    && (result_kind != Some("success")
                        || key.is_none()
                        || evidence
                            .pointer("/closure/approval")
                            .is_none_or(Value::is_null))
                {
                    invalid(
                        report,
                        "approval",
                        "proof.verify.release.approval",
                        Some(record.digest),
                        Some(record.sequence),
                    );
                }
            }
            _ => invalid(
                report,
                "localized_consequence",
                "proof.verify.consequence.decision",
                Some(record.digest),
                Some(record.sequence),
            ),
        }
    }
    if localized == 0 {
        invalid(
            report,
            "localized_consequence",
            "proof.verify.consequence.none",
            None,
            None,
        );
    }
    report.valid("localized_consequence");
    report.valid("application_key_history");
    report.valid("approval");
}

fn artifact_has_role(
    loaded: &LoadedBundle,
    role: EvidenceRole,
    reference: crate::model::ArtifactRef,
) -> bool {
    loaded
        .bundle
        .artifacts
        .iter()
        .filter(|descriptor| descriptor.role == role && descriptor.artifact == reference)
        .count()
        == 1
}

fn localized_problem_is_exact(value: &Value) -> bool {
    let Some(code) = string(value, "code") else {
        return false;
    };
    let expected = match code {
        "proof.resource.not_found" => (
            "urn:proof:problem:resource-not-found",
            "The exact localized-content resource was not found",
        ),
        "proof.input.unsupported_version" => (
            "urn:proof:problem:unsupported-version",
            "The operation is unsupported for the current artifact version",
        ),
        "proof.input.schema_mismatch" => (
            "urn:proof:problem:input-schema-mismatch",
            "The localized-content input violates its closed contract",
        ),
        "proof.input.intent_mismatch" => (
            "urn:proof:problem:intent-mismatch",
            "The operation differs from the immutable resource intent",
        ),
        "proof.state.source_conflict" => (
            "urn:proof:problem:state-conflict",
            "The locale-neutral source precondition changed",
        ),
        "proof.state.target_conflict" => (
            "urn:proof:problem:state-conflict",
            "The exact target rendition precondition changed",
        ),
        "proof.state.conflict" => (
            "urn:proof:problem:state-conflict",
            "The localized-content baseline changed concurrently",
        ),
        "proof.changeset.duplicate_target" => (
            "urn:proof:problem:state-conflict",
            "The ChangeSet already has an active Edit for this target",
        ),
        "proof.changeset.invalid_supersession" => (
            "urn:proof:problem:state-conflict",
            "The requested Edit supersession edge is invalid",
        ),
        "proof.validation.repair_evidence_invalid" => (
            "urn:proof:problem:repair-evidence-invalid",
            "The repair evidence does not match the latest invalid result",
        ),
        "proof.changeset.not_draft" => (
            "urn:proof:problem:changeset-lifecycle",
            "Localized Edits require a Draft ChangeSet",
        ),
        "proof.changeset.not_ready" => (
            "urn:proof:problem:changeset-lifecycle",
            "The localized ChangeSet is not Ready",
        ),
        "proof.changeset.not_submitted" => (
            "urn:proof:problem:changeset-lifecycle",
            "The localized ChangeSet is not Submitted",
        ),
        "proof.changeset.not_approved" => (
            "urn:proof:problem:changeset-lifecycle",
            "The localized ChangeSet is not Approved",
        ),
        "proof.evidence.incomplete" => (
            "urn:proof:problem:evidence-incomplete",
            "Localized-content evidence is incomplete",
        ),
        "proof.input.limit_exceeded" => (
            "urn:proof:problem:input-limit-exceeded",
            "The localized-content operation exceeds its committed budget",
        ),
        "proof.policy.denied" => (
            "urn:proof:problem:policy-denied",
            "Policy denied the exact localized-content operation",
        ),
        _ => return false,
    };
    object_keys_exact(value, &["code", "detail", "retryable", "title", "type"])
        && value.get("detail").is_some_and(Value::is_null)
        && value.get("retryable") == Some(&Value::Bool(false))
        && string(value, "type") == Some(expected.0)
        && string(value, "title") == Some(expected.1)
}

fn semantic_timestamp_is_exact(
    spec: &operation::OperationSpec,
    input: &LoadedArtifact,
    evidence: &Value,
) -> bool {
    let normalized = input.value.get("normalized_input");
    let expected = match spec.name {
        "context.build" => normalized.and_then(|value| value.get("created_at")),
        "changeset.create" => normalized.and_then(|value| value.get("created_at")),
        "changeset.submit" => normalized.and_then(|value| value.get("submitted_at")),
        "changeset.commit" => normalized.and_then(|value| value.get("committed_at")),
        "edition.create" => normalized.and_then(|value| value.get("created_at")),
        "release.create" => normalized.and_then(|value| value.get("released_at")),
        "object.query_released" => normalized.and_then(|value| value.get("evaluated_at")),
        _ => None,
    };
    match expected {
        Some(expected) => evidence.get("semantic_timestamp") == Some(expected),
        None => evidence
            .get("semantic_timestamp")
            .is_some_and(Value::is_null),
    }
}

fn application_idempotency_is_exact(
    loaded: &LoadedBundle,
    spec: &operation::OperationSpec,
    input: &LoadedArtifact,
    decision: &Value,
    evidence: &Value,
    result_kind: Option<&str>,
) -> bool {
    let Some(idempotency) = evidence.get("application_idempotency") else {
        return false;
    };
    if !object_keys_exact(idempotency, &["key", "kind"]) {
        return false;
    }
    let key = string(idempotency, "key");
    match spec.idempotency {
        operation::Idempotency::None => {
            string(idempotency, "kind") == Some("none")
                && idempotency.get("key").is_some_and(Value::is_null)
        }
        operation::Idempotency::Required => {
            string(idempotency, "kind") == Some("required")
                && key.is_some_and(operation::uuid_v7)
                && idempotency.get("key") == input.value.get("idempotency_key")
                && idempotency.get("key")
                    == input.value.pointer("/normalized_input/idempotency_key")
        }
        operation::Idempotency::Derived => {
            if string(idempotency, "kind") != Some("derived") {
                return false;
            }
            let derived = derive_application_key(loaded, spec, input, decision);
            match (result_kind, derived) {
                (Some("success"), Some(expected)) => key == Some(expected.as_str()),
                (Some("failure"), Some(expected)) => {
                    key == Some(expected.as_str())
                        || idempotency.get("key").is_some_and(Value::is_null)
                }
                (Some("failure"), None) => idempotency.get("key").is_some_and(Value::is_null),
                _ => false,
            }
        }
    }
}

fn derive_application_key(
    loaded: &LoadedBundle,
    spec: &operation::OperationSpec,
    input: &LoadedArtifact,
    _decision: &Value,
) -> Option<String> {
    let normalized = input.value.get("normalized_input")?;
    let value = match spec.name {
        "changeset.submit" => json!({
            "api_version": "proof.dev/application-idempotency-key/v1",
            "changeset_id": string(normalized, "changeset_id")?,
            "operation": "changeset.submit/v2",
            "workspace_id": loaded.bundle.workspace_id,
        }),
        "changeset.validate" => {
            let changeset_id = string(normalized, "changeset_id")?;
            let changeset = unique_role_artifact_by(loaded, EvidenceRole::ChangeSet, |artifact| {
                string(&artifact.value, "api_version") == Some("proof.dev/changeset/v2")
                    && string(&artifact.value, "changeset_id") == Some(changeset_id)
            })?;
            let context = exact_role_artifact(
                loaded,
                EvidenceRole::ContextPack,
                digest_field(&changeset.value, "context_pack_digest"),
            )?;
            let proposal_digest = domain_digest(ArtifactKind::ChangeSetV2, &changeset.bytes);
            json!({
                "api_version": "proof.dev/application-idempotency-key/v1",
                "changeset_id": changeset_id,
                "operation": "changeset.validate/v2",
                "policy_digest": digest_field(&context.value, "policy_digest")?,
                "proposal_digest": proposal_digest,
                "validator": "proof/localized-content/1",
                "workspace_id": loaded.bundle.workspace_id,
            })
        }
        _ => return None,
    };
    canonical_bytes(&value)
        .ok()
        .map(|bytes| domain_digest(ArtifactKind::OperationEffectV1, &bytes).to_string())
}

fn unique_role_artifact_by<F>(
    loaded: &LoadedBundle,
    role: EvidenceRole,
    predicate: F,
) -> Option<&LoadedArtifact>
where
    F: Fn(&LoadedArtifact) -> bool,
{
    let mut matches = artifacts_for_role(loaded, role).filter(|artifact| predicate(artifact));
    let artifact = matches.next()?;
    matches.next().is_none().then_some(artifact)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the application effect is a join across the signed operation, canonical result, and exact companion"
)]
fn localized_effect_is_exact(
    loaded: &LoadedBundle,
    spec: &operation::OperationSpec,
    input: &LoadedArtifact,
    decision: &Value,
    result_kind: Option<&str>,
    result_ref: crate::model::ArtifactRef,
    result: &Value,
    effect_ref: crate::model::ArtifactRef,
    effect: &Value,
) -> bool {
    if !artifact_has_role(loaded, EvidenceRole::LocalizedResult, result_ref)
        || !artifact_has_role(loaded, EvidenceRole::ApplicationEffect, effect_ref)
    {
        return false;
    }
    if result_kind == Some("failure") {
        return effect_ref == result_ref && effect == result;
    }
    if result_kind != Some("success") {
        return false;
    }
    match spec.consequence {
        operation::Consequence::EvidenceOnly => {
            effect_ref == result_ref
                && effect == result
                && (spec.name != "object.query_released"
                    || released_query_effect_is_exact(loaded, input, decision, effect))
        }
        operation::Consequence::Validation => {
            effect_ref.artifact_kind == ArtifactKind::ValidationResultsV2
                && schema::localized_artifact(effect)
                && digest_field(result, "validation_results_digest") == Some(effect_ref.digest)
                && result.get("attempt") == effect.get("attempt")
                && result.get("changeset_id") == effect.get("changeset_id")
                && result.get("effective_leaf_digest") == effect.get("effective_leaf_digest")
                && result.get("findings") == effect.get("findings")
                && result.get("previous_validation_result_digest")
                    == effect.get("previous_validation_result_digest")
                && result.get("proposal_digest") == effect.get("proposal_digest")
                && result.get("valid") == effect.get("valid")
                && match result.get("valid").and_then(Value::as_bool) {
                    Some(true) => {
                        string(result, "status") == Some("ready")
                            && digest_field(result, "sealed_changeset_digest").is_some_and(
                                |digest| {
                                    exact_role_artifact(
                                        loaded,
                                        EvidenceRole::ChangeSet,
                                        Some(digest),
                                    )
                                    .is_some_and(|seal| {
                                        string(&seal.value, "api_version")
                                            == Some("proof.dev/changeset-seal/v2")
                                            && digest_field(&seal.value, "proposal_digest")
                                                == digest_field(result, "proposal_digest")
                                            && digest_field(
                                                &seal.value,
                                                "validation_results_digest",
                                            ) == Some(effect_ref.digest)
                                    })
                                },
                            )
                    }
                    Some(false) => {
                        string(result, "status") == Some("draft")
                            && result
                                .get("sealed_changeset_digest")
                                .is_some_and(Value::is_null)
                    }
                    None => false,
                }
        }
        operation::Consequence::Release => {
            effect_ref.artifact_kind == ArtifactKind::ReleaseV2
                && schema::localized_artifact(effect)
                && result.get("release_manifest") == Some(effect)
                && digest_field(result, "release_digest") == Some(effect_ref.digest)
                && result.get("release_id") == effect.get("release_id")
                && result.get("proof_id") == effect.get("proof_id")
                && digest_field(result, "proof_envelope_digest").is_some_and(|digest| {
                    loaded.bundle.artifacts.iter().any(|descriptor| {
                        descriptor.role == EvidenceRole::ReleaseProofEnvelope
                            && descriptor.artifact.digest == digest
                            && loaded.artifacts.contains_key(&descriptor.artifact)
                    })
                })
        }
        operation::Consequence::Context
        | operation::Consequence::ChangeSetCreate
        | operation::Consequence::ChangeSetAdd
        | operation::Consequence::Submission
        | operation::Consequence::Commit
        | operation::Consequence::Edition => {
            effect_ref.artifact_kind == ArtifactKind::OperationEffectV1
                && operation_effect_wrapper_is_exact(loaded, spec, input, decision, result, effect)
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "released-query verification joins the selected release, edition state, ordered targets, and immutable rendition/source/schema evidence"
)]
fn released_query_effect_is_exact(
    loaded: &LoadedBundle,
    input: &LoadedArtifact,
    decision: &Value,
    result: &Value,
) -> bool {
    let normalized = input.value.get("normalized_input").unwrap_or(&Value::Null);
    let Some(evaluated_at) = string(normalized, "evaluated_at").and_then(parse_timestamp) else {
        return false;
    };
    if result.get("workspace_id") != Some(&Value::String(loaded.bundle.workspace_id.clone()))
        || result.get("environment_id") != normalized.get("environment_id")
    {
        return false;
    }
    let Some(release_id) = string(result, "release_id") else {
        return false;
    };
    let mut releases = artifacts_for_role(loaded, EvidenceRole::ReleaseManifest)
        .filter(|artifact| {
            string(&artifact.value, "workspace_id") == Some(loaded.bundle.workspace_id.as_str())
                && artifact.value.get("environment_id") == normalized.get("environment_id")
                && string(&artifact.value, "api_version") == Some("proof.dev/release/v2")
                && string(&artifact.value, "released_at")
                    .and_then(parse_timestamp)
                    .is_some_and(|released_at| released_at <= evaluated_at)
        })
        .collect::<Vec<_>>();
    releases.sort_by_key(|artifact| u64_field(&artifact.value, "release_sequence"));
    let Some(release) = releases.last().copied() else {
        return false;
    };
    let current_sequence = u64_field(&release.value, "release_sequence");
    if current_sequence.is_none()
        || releases
            .iter()
            .rev()
            .skip(1)
            .any(|candidate| u64_field(&candidate.value, "release_sequence") == current_sequence)
        || string(&release.value, "release_id") != Some(release_id)
        || release.value.get("edition") != result.get("edition")
    {
        return false;
    }
    let Some(edition_reference) = result.get("edition") else {
        return false;
    };
    let Some(edition) = exact_role_artifact(
        loaded,
        EvidenceRole::Edition,
        reference_digest(edition_reference),
    ) else {
        return false;
    };
    if string(&edition.value, "api_version") != Some("proof.dev/edition/v2")
        || edition.value.get("edition_id") != edition_reference.get("edition_id")
        || string(&edition.value, "workspace_id") != Some(loaded.bundle.workspace_id.as_str())
    {
        return false;
    }
    let Some(state) = exact_role_artifact(
        loaded,
        EvidenceRole::KnownState,
        edition
            .value
            .pointer("/state/digest")
            .and_then(Value::as_str)
            .and_then(Digest::parse),
    ) else {
        return false;
    };
    if edition
        .value
        .get("state")
        .and_then(|reference| reference.get("authoritative_sequence"))
        != state.value.get("authoritative_sequence")
        || string(&state.value, "workspace_id") != Some(loaded.bundle.workspace_id.as_str())
    {
        return false;
    }
    let Some(targets) = normalized.get("targets").and_then(Value::as_array) else {
        return false;
    };
    let Some(renditions) = result.get("renditions").and_then(Value::as_array) else {
        return false;
    };
    if targets.len() != renditions.len() {
        return false;
    }
    let expected_schema_ids = renditions
        .iter()
        .filter_map(|rendition| string(rendition, "schema_id"))
        .collect::<BTreeSet<_>>();
    let requested_schema_ids = decision
        .pointer("/requested_resources/schema_ids")
        .and_then(Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .map(Value::as_str)
                .collect::<Option<BTreeSet<_>>>()
        });
    if requested_schema_ids.as_ref() != Some(&expected_schema_ids) {
        return false;
    }
    targets.iter().zip(renditions).all(|(target, rendition)| {
        if target.get("object_id") != rendition.get("object_id")
            || target.get("locale") != rendition.get("locale")
        {
            return false;
        }
        let Some(revision) = exact_role_artifact(
            loaded,
            EvidenceRole::LocaleRevision,
            digest_field(rendition, "rendition_digest"),
        ) else {
            return false;
        };
        let revision_matches = revision.value.get("object_id") == rendition.get("object_id")
            && revision.value.get("locale") == rendition.get("locale")
            && revision.value.get("revision") == rendition.get("rendition_revision")
            && revision.value.get("content") == rendition.get("content")
            && revision.value.get("schema_id") == rendition.get("schema_id")
            && revision.value.get("schema_version") == rendition.get("schema_version")
            && revision.value.get("source_object_digest") == rendition.get("source_digest")
            && revision.value.get("source_object_revision") == rendition.get("source_revision");
        let state_matches = [
            edition.value.get("renditions"),
            state.value.get("renditions"),
        ]
        .into_iter()
        .all(|values| {
            values.and_then(Value::as_array).is_some_and(|values| {
                values.iter().any(|entry| {
                    entry.get("object_id") == rendition.get("object_id")
                        && entry.get("locale") == rendition.get("locale")
                        && entry.get("rendition_digest") == rendition.get("rendition_digest")
                        && entry.get("revision") == rendition.get("rendition_revision")
                        && entry.get("schema_id") == rendition.get("schema_id")
                        && entry.get("schema_version") == rendition.get("schema_version")
                        && entry.get("source_object_digest") == rendition.get("source_digest")
                })
            })
        });
        let source_matches = exact_role_artifact(
            loaded,
            EvidenceRole::Object,
            digest_field(rendition, "source_digest"),
        )
        .is_some_and(|source| {
            source.value.get("object_id") == rendition.get("object_id")
                && source.value.get("revision") == rendition.get("source_revision")
                && source.value.get("schema_id") == rendition.get("schema_id")
                && source.value.get("schema_version") == rendition.get("schema_version")
                && string(&source.value, "lifecycle_state") == Some("active")
        });
        let schema_matches = edition
            .value
            .get("schemas")
            .and_then(Value::as_array)
            .and_then(|schemas| {
                schemas.iter().find(|schema| {
                    schema.get("schema_id") == rendition.get("schema_id")
                        && schema.get("schema_version") == rendition.get("schema_version")
                })
            })
            .and_then(|schema| {
                exact_role_artifact(
                    loaded,
                    EvidenceRole::Schema,
                    digest_field(schema, "document_digest"),
                )
            })
            .is_some_and(|schema| {
                schema::document_accepts(
                    &schema.value,
                    rendition.get("content").unwrap_or(&Value::Null),
                )
            });
        revision_matches && state_matches && source_matches && schema_matches
    })
}

fn operation_effect_wrapper_is_exact(
    loaded: &LoadedBundle,
    spec: &operation::OperationSpec,
    input: &LoadedArtifact,
    decision: &Value,
    result: &Value,
    effect: &Value,
) -> bool {
    let expected_kind = format!("{}/v2", spec.name);
    if string(effect, "api_version") != Some("proof.dev/operation-effect/v1")
        || string(effect, "operation_kind") != Some(expected_kind.as_str())
    {
        return false;
    }
    let normalized = input.value.get("normalized_input").unwrap_or(&Value::Null);
    let request_digest = canonical_bytes(normalized)
        .ok()
        .map(|bytes| domain_digest(ArtifactKind::OperationEffectV1, &bytes));
    match spec.consequence {
        operation::Consequence::Context => {
            object_keys_exact(
                effect,
                &["api_version", "operation_kind", "request_digest", "result"],
            ) && digest_field(effect, "request_digest") == request_digest
                && effect.get("result")
                    == Some(&json!({
                        "context_pack_digest": result.get("context_pack_digest"),
                        "context_pack_id": result.get("context_pack_id"),
                    }))
                && digest_field(result, "context_pack_digest").is_some_and(|digest| {
                    exact_role_artifact(loaded, EvidenceRole::ContextPack, Some(digest))
                        .is_some_and(|artifact| result.get("manifest") == Some(&artifact.value))
                })
        }
        operation::Consequence::ChangeSetCreate | operation::Consequence::ChangeSetAdd => {
            object_keys_exact(
                effect,
                &["api_version", "operation_kind", "request_digest", "result"],
            ) && digest_field(effect, "request_digest") == request_digest
                && effect.get("result") == Some(result)
        }
        operation::Consequence::Submission => {
            object_keys_exact(effect, &["api_version", "operation_kind", "result"])
                && effect.get("result")
                    == Some(&json!({
                        "approval": Value::Null,
                        "changeset_id": result.get("changeset_id"),
                        "occurred_at": result.get("submitted_at"),
                        "principal_id": decision.get("requesting_principal_id"),
                        "sealed_changeset_digest": result.get("sealed_changeset_digest"),
                        "validation_results_digest": result.get("validation_results_digest"),
                    }))
        }
        operation::Consequence::Commit => {
            let Some(renditions) = result.get("renditions").and_then(Value::as_array) else {
                return false;
            };
            let compact = renditions
                .iter()
                .map(|rendition| {
                    let bytes = canonical_bytes(rendition).ok()?;
                    Some(json!({
                        "digest": domain_digest(ArtifactKind::ObjectLocaleRevisionV1, &bytes),
                        "edit_id": rendition.get("edit_id"),
                        "locale": rendition.get("locale"),
                        "object_id": rendition.get("object_id"),
                        "revision": rendition.get("revision"),
                    }))
                })
                .collect::<Option<Vec<_>>>();
            object_keys_exact(
                effect,
                &["api_version", "operation_kind", "request_digest", "result"],
            ) && digest_field(effect, "request_digest") == request_digest
                && compact.is_some_and(|renditions| {
                    effect.get("result")
                        == Some(&json!({
                            "changeset_id": result.get("changeset_id"),
                            "committed_at": result.get("committed_at"),
                            "previous_state": result.get("previous_state"),
                            "renditions": renditions,
                            "resulting_state": result.get("resulting_state"),
                            "sealed_changeset_digest": result.get("sealed_changeset_digest"),
                            "validation_results_digest": result.get("validation_results_digest"),
                        }))
                })
        }
        operation::Consequence::Edition => {
            object_keys_exact(
                effect,
                &["api_version", "operation_kind", "request_digest", "result"],
            ) && digest_field(effect, "request_digest") == request_digest
                && effect.get("result")
                    == Some(&json!({
                        "changeset_id": normalized.get("changeset_id"),
                        "edition_digest": result.get("edition_digest"),
                        "edition_id": result.get("edition_id"),
                        "state": result.get("state"),
                    }))
                && digest_field(result, "edition_digest").is_some_and(|digest| {
                    exact_role_artifact(loaded, EvidenceRole::Edition, Some(digest))
                        .is_some_and(|artifact| result.get("manifest") == Some(&artifact.value))
                })
        }
        operation::Consequence::EvidenceOnly
        | operation::Consequence::Validation
        | operation::Consequence::Release => false,
    }
}

fn localized_closure_is_exact(
    loaded: &LoadedBundle,
    records: &BTreeMap<Digest, &VerifiedAuthorityRecord>,
    spec: &operation::OperationSpec,
    input: &LoadedArtifact,
    decision: &Value,
    evidence: &Value,
    result_kind: Option<&str>,
    effect: &Value,
) -> bool {
    let Some(closure) = evidence.get("closure") else {
        return false;
    };
    if spec.name == "object.query_released" {
        return released_closure_is_exact(loaded, closure, decision, effect);
    }
    intent_closure_is_exact(
        loaded,
        records,
        spec,
        input,
        decision,
        evidence,
        closure,
        result_kind,
        effect,
    )
}

fn released_closure_is_exact(
    loaded: &LoadedBundle,
    closure: &Value,
    decision: &Value,
    result: &Value,
) -> bool {
    if !object_keys_exact(closure, &["edition_id", "release_id", "schema_ids"])
        || !sorted_unique_strings(closure.get("schema_ids"), 0, 100)
    {
        return false;
    }
    let editions = decision
        .pointer("/requested_resources/edition_ids")
        .and_then(Value::as_array);
    let releases = decision
        .pointer("/requested_resources/release_ids")
        .and_then(Value::as_array);
    let schemas = decision
        .pointer("/requested_resources/schema_ids")
        .and_then(Value::as_array);
    editions.is_some_and(|values| optional_singleton_is_exact(closure.get("edition_id"), values))
        && releases
            .is_some_and(|values| optional_singleton_is_exact(closure.get("release_id"), values))
        && closure.get("schema_ids").and_then(Value::as_array) == schemas
        && closure.get("edition_id") == result.pointer("/edition/edition_id")
        && closure.get("release_id") == result.get("release_id")
        && result
            .get("renditions")
            .and_then(Value::as_array)
            .and_then(|renditions| {
                renditions
                    .iter()
                    .map(|rendition| string(rendition, "schema_id"))
                    .collect::<Option<BTreeSet<_>>>()
            })
            .is_some_and(|result_schemas| {
                closure
                    .get("schema_ids")
                    .and_then(Value::as_array)
                    .is_some_and(|closure_schemas| {
                        closure_schemas
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<BTreeSet<_>>()
                            == result_schemas
                    })
            })
        && string(closure, "release_id").is_none_or(|release_id| {
            unique_role_artifact_by(loaded, EvidenceRole::ReleaseManifest, |artifact| {
                string(&artifact.value, "release_id") == Some(release_id)
            })
            .is_some()
        })
}

fn optional_singleton_is_exact(actual: Option<&Value>, expected: &[Value]) -> bool {
    match expected {
        [] => actual.is_some_and(Value::is_null),
        [only] => actual == Some(only),
        _ => false,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the signed intent closure binds its immutable intent, context, changeset, and Human approval preimages"
)]
fn intent_closure_is_exact(
    loaded: &LoadedBundle,
    records: &BTreeMap<Digest, &VerifiedAuthorityRecord>,
    spec: &operation::OperationSpec,
    input: &LoadedArtifact,
    decision: &Value,
    evidence: &Value,
    closure: &Value,
    result_kind: Option<&str>,
    effect: &Value,
) -> bool {
    if !object_keys_exact(
        closure,
        &[
            "approval",
            "changeset",
            "context",
            "context_fresh",
            "resource_intent",
            "validator",
        ],
    ) || !closure.get("context_fresh").is_some_and(Value::is_boolean)
        || string(closure, "validator") != Some("proof/localized-content/1")
    {
        return false;
    }
    let context_fresh = closure
        .get("context_fresh")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if (result_kind == Some("success") && !context_fresh)
        || (!context_fresh
            && result_kind == Some("failure")
            && string(effect, "code") != Some("proof.policy.denied"))
    {
        return false;
    }
    let Some(intent_closure) = closure.get("resource_intent") else {
        return false;
    };
    if !object_keys_exact(
        intent_closure,
        &["intent_digest", "intent_id", "issued_by_principal_id"],
    ) {
        return false;
    }
    let Some(intent_digest) = digest_field(intent_closure, "intent_digest") else {
        return false;
    };
    let Some(intent) =
        exact_role_artifact(loaded, EvidenceRole::ResourceIntent, Some(intent_digest))
    else {
        return false;
    };
    if string(&intent.value, "api_version") != Some("proof.dev/content-resource-intent/v1")
        || intent.value.get("intent_id") != intent_closure.get("intent_id")
        || intent.value.get("issued_by_principal_id")
            != intent_closure.get("issued_by_principal_id")
        || intent.value.get("issued_by_principal_id") != decision.get("requesting_principal_id")
        || string(&intent.value, "workspace_id") != Some(loaded.bundle.workspace_id.as_str())
    {
        return false;
    }
    let (context_closure, context) = match closure.get("context") {
        Some(Value::Null) if result_kind == Some("failure") => (None, None),
        Some(value) => {
            if !object_keys_exact(
                value,
                &[
                    "context_pack_digest",
                    "context_pack_id",
                    "limits",
                    "policy_digest",
                ],
            ) || !value.get("limits").is_some_and(|limits| {
                object_keys_exact(
                    limits,
                    &[
                        "max_bytes",
                        "max_edits",
                        "max_objects",
                        "max_validation_attempts",
                    ],
                )
            }) {
                return false;
            }
            let Some(context) = exact_role_artifact(
                loaded,
                EvidenceRole::ContextPack,
                digest_field(value, "context_pack_digest"),
            ) else {
                return false;
            };
            if context.value.get("context_pack_id") != value.get("context_pack_id")
                || context.value.get("limits") != value.get("limits")
                || context.value.get("policy_digest") != value.get("policy_digest")
                || digest_field(&context.value, "resource_intent_digest") != Some(intent_digest)
                || context.value.get("principal_id") != decision.get("requesting_principal_id")
            {
                return false;
            }
            (Some(value), Some(context))
        }
        None => return false,
    };
    let changeset = match closure.get("changeset") {
        Some(Value::Null) => None,
        Some(value) => {
            if !object_keys_exact(
                value,
                &[
                    "changeset_id",
                    "context_pack_digest",
                    "context_pack_id",
                    "resource_intent_digest",
                    "resource_intent_id",
                ],
            ) {
                return false;
            }
            let Some(artifact) =
                unique_role_artifact_by(loaded, EvidenceRole::ChangeSet, |artifact| {
                    string(&artifact.value, "api_version") == Some("proof.dev/changeset/v2")
                        && artifact.value.get("changeset_id") == value.get("changeset_id")
                })
            else {
                return false;
            };
            if artifact.value.get("context_pack_digest") != value.get("context_pack_digest")
                || artifact.value.get("context_pack_id") != value.get("context_pack_id")
                || artifact.value.get("resource_intent_digest")
                    != value.get("resource_intent_digest")
                || artifact.value.get("resource_intent_id") != value.get("resource_intent_id")
                || artifact.value.get("principal_id") != decision.get("requesting_principal_id")
                || value.get("resource_intent_digest") != intent_closure.get("intent_digest")
                || value.get("resource_intent_id") != intent_closure.get("intent_id")
                || context_closure.is_some_and(|context| {
                    value.get("context_pack_digest") != context.get("context_pack_digest")
                        || value.get("context_pack_id") != context.get("context_pack_id")
                })
            {
                return false;
            }
            Some(artifact)
        }
        None => return false,
    };
    let normalized = input.value.get("normalized_input").unwrap_or(&Value::Null);
    let change_set_expectation = match spec.name {
        "context.build" | "changeset.create" => changeset.is_none(),
        "object.query_released" => true,
        _ => changeset.is_some_and(|changeset| {
            normalized
                .get("changeset_id")
                .or_else(|| effect.get("changeset_id"))
                .or_else(|| effect.pointer("/changeset/changeset_id"))
                .or_else(|| effect.pointer("/changeset_id"))
                .or_else(|| effect.pointer("/result/changeset_id"))
                .or_else(|| effect.get("changeset_id"))
                .is_none_or(|expected| changeset.value.get("changeset_id") == Some(expected))
        }),
    };
    if !change_set_expectation {
        return false;
    }
    let _ = context;
    let approval_required = result_kind == Some("success")
        && matches!(
            spec.consequence,
            operation::Consequence::Commit
                | operation::Consequence::Edition
                | operation::Consequence::Release
        );
    match closure.get("approval") {
        Some(Value::Null) => !approval_required,
        Some(approval) => signed_approval_is_exact(
            loaded, records, approval, changeset, decision, evidence, effect,
        ),
        None => false,
    }
}

fn signed_approval_is_exact(
    loaded: &LoadedBundle,
    records: &BTreeMap<Digest, &VerifiedAuthorityRecord>,
    approval: &Value,
    changeset: Option<&LoadedArtifact>,
    decision: &Value,
    evidence: &Value,
    effect: &Value,
) -> bool {
    if !object_keys_exact(
        approval,
        &[
            "approval_name",
            "approved_at",
            "effect_digest",
            "principal_id",
        ],
    ) {
        return false;
    }
    let Some(changeset) = changeset else {
        return false;
    };
    let Some(approval_artifact) = exact_role_artifact(
        loaded,
        EvidenceRole::Approval,
        digest_field(approval, "effect_digest"),
    ) else {
        return false;
    };
    let approved_at = string(approval, "approved_at").and_then(parse_timestamp);
    let approver = string(approval, "principal_id");
    let approval_status = principal_status_at(
        records,
        approver,
        decision
            .get("authority_sequence")
            .and_then(Value::as_u64)
            .and_then(|sequence| sequence.checked_sub(1)),
        approved_at,
    );
    if approval_status.is_none_or(|status| {
        string(&status.value, "principal_type") != Some("human")
            || status.value.get("enabled") != Some(&Value::Bool(true))
    }) {
        return false;
    }
    if !operation_effect_shape(&approval_artifact.value, "changeset.approve/v2")
        || approval_artifact.value.pointer("/result/approval") != approval.get("approval_name")
        || approval_artifact.value.pointer("/result/occurred_at") != approval.get("approved_at")
        || approval_artifact.value.pointer("/result/principal_id") != approval.get("principal_id")
        || approval_artifact.value.pointer("/result/changeset_id")
            != changeset.value.get("changeset_id")
    {
        return false;
    }
    let sealed = digest_path(
        &approval_artifact.value,
        &["result", "sealed_changeset_digest"],
    );
    let validation = digest_path(
        &approval_artifact.value,
        &["result", "validation_results_digest"],
    );
    let matching_seal = artifacts_for_role(loaded, EvidenceRole::ChangeSet)
        .filter(|artifact| {
            string(&artifact.value, "api_version") == Some("proof.dev/changeset-seal/v2")
                && object_keys_exact(
                    &artifact.value,
                    &[
                        "api_version",
                        "proposal_digest",
                        "validation_results_digest",
                    ],
                )
                && digest_field(&artifact.value, "proposal_digest")
                    == Some(domain_digest(ArtifactKind::ChangeSetV2, &changeset.bytes))
                && digest_field(&artifact.value, "validation_results_digest") == validation
        })
        .map(|artifact| domain_digest(ArtifactKind::ChangeSetV2, &artifact.bytes));
    let mut matching_seal = matching_seal;
    let exact_seal = matching_seal
        .next()
        .filter(|_| matching_seal.next().is_none());
    if sealed != exact_seal {
        return false;
    }
    let Some(validation_digest) = validation else {
        return false;
    };
    if exact_role_artifact(
        loaded,
        EvidenceRole::ValidationAttempt,
        Some(validation_digest),
    )
    .is_none_or(|artifact| !schema::localized_artifact(&artifact.value))
    {
        return false;
    }
    let mut submissions = artifacts_for_role(loaded, EvidenceRole::Submission).filter(|artifact| {
        operation_effect_shape(&artifact.value, "changeset.submit/v2")
            && artifact.value.pointer("/result/changeset_id") == changeset.value.get("changeset_id")
            && digest_path(&artifact.value, &["result", "sealed_changeset_digest"]) == sealed
            && digest_path(&artifact.value, &["result", "validation_results_digest"]) == validation
            && artifact.value.pointer("/result/principal_id")
                == decision.get("requesting_principal_id")
            && artifact
                .value
                .pointer("/result/approval")
                .is_some_and(Value::is_null)
    });
    let Some(submission) = submissions.next().filter(|_| submissions.next().is_none()) else {
        return false;
    };
    let submitted = submission
        .value
        .pointer("/result/occurred_at")
        .and_then(Value::as_str)
        .and_then(parse_timestamp);
    let approved = approved_at;
    let semantic = string(evidence, "semantic_timestamp").and_then(parse_timestamp);
    let effect_time = string(effect, "released_at").and_then(parse_timestamp);
    submitted
        .zip(approved)
        .zip(semantic.or(effect_time))
        .is_some_and(|((submitted, approved), consequence)| {
            submitted <= approved && approved <= consequence
        })
}

fn operation_effect_shape(value: &Value, operation_kind: &str) -> bool {
    object_keys_exact(value, &["api_version", "operation_kind", "result"])
        && string(value, "api_version") == Some("proof.dev/operation-effect/v1")
        && string(value, "operation_kind") == Some(operation_kind)
        && value.get("result").is_some_and(|result| {
            object_keys_exact(
                result,
                &[
                    "approval",
                    "changeset_id",
                    "occurred_at",
                    "principal_id",
                    "sealed_changeset_digest",
                    "validation_results_digest",
                ],
            )
        })
}

fn verify_subject_opening(
    loaded: &LoadedBundle,
    trust: &TrustPolicy,
    records: &[VerifiedAuthorityRecord],
    report: &mut Report,
) {
    let target = records.iter().find(|record| {
        record.digest == loaded.bundle.entrypoints.target_authorization_record_digest
    });
    let commitment =
        target.and_then(|record| digest_field(&record.value, "requesting_subject_commitment"));
    let descriptors = loaded
        .bundle
        .artifacts
        .iter()
        .filter(|descriptor| descriptor.role == EvidenceRole::SubjectOpening)
        .collect::<Vec<_>>();
    if descriptors.len() != 1 {
        invalid(
            report,
            "subject_opening",
            "proof.verify.subject.descriptor_count",
            commitment,
            None,
        );
        return;
    }
    let Some(descriptor) = descriptors.first().copied() else {
        incomplete(
            report,
            "subject_opening",
            "proof.verify.subject.descriptor_missing",
            commitment,
            None,
        );
        return;
    };
    if loaded.missing_external.contains(&descriptor.artifact) {
        if trust.disclosure.requesting_subject_opening == OpeningRequirement::Optional {
            report.not_required("subject_opening");
        } else {
            incomplete(
                report,
                "subject_opening",
                "proof.verify.subject.opening_required",
                commitment,
                None,
            );
        }
        return;
    }
    let Some(opening) = loaded.artifacts.get(&descriptor.artifact) else {
        return;
    };
    let input = opening.value.get("commitment_input");
    let reproduced = input
        .and_then(|input| canonical_bytes(input).ok())
        .map(|bytes| domain_digest(ArtifactKind::AuthenticatedSubjectCommitmentV1, &bytes));
    let blind = string(&opening.value, "blind");
    let blind_valid = blind
        .and_then(|blind| {
            URL_SAFE_NO_PAD
                .decode(blind)
                .ok()
                .map(|bytes| (blind, bytes))
        })
        .is_some_and(|(encoded, bytes)| {
            bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == encoded
        });
    let subject = opening.value.get("requesting_subject");
    let authenticated_subject = input.and_then(|value| value.get("authenticated_subject"));
    let subject_matches =
        subject
            .zip(authenticated_subject)
            .is_some_and(|(subject, authenticated)| {
                object_keys_exact(subject, &["provider", "subject"])
                    && object_keys_exact(authenticated, &["api_version", "provider", "subject"])
                    && string(authenticated, "api_version")
                        == Some("proof.dev/authenticated-subject/v1")
                    && string(authenticated, "provider") == Some("os/unix")
                    && subject.get("provider") == authenticated.get("provider")
                    && subject.get("subject") == authenticated.get("subject")
                    && string(authenticated, "subject").is_some_and(valid_unix_subject)
            });
    let wrapper_matches = object_keys_exact(
        &opening.value,
        &[
            "api_version",
            "blind",
            "commitment_input",
            "requesting_subject",
            "requesting_subject_commitment",
            "workspace_id",
        ],
    ) && input.is_some_and(|input| {
        object_keys_exact(
            input,
            &[
                "api_version",
                "authenticated_subject",
                "blind",
                "workspace_id",
            ],
        ) && string(input, "api_version") == Some("proof.dev/authenticated-subject-commitment/v1")
    }) && string(&opening.value, "api_version")
        == Some("proof.dev/authenticated-subject-opening/v1")
        && digest_field(&opening.value, "requesting_subject_commitment") == commitment
        && opening.value.get("blind") == input.and_then(|value| value.get("blind"))
        && blind_valid
        && subject_matches
        && input.and_then(|value| string(value, "workspace_id"))
            == Some(loaded.bundle.workspace_id.as_str());
    if reproduced != commitment
        || !wrapper_matches
        || string(&opening.value, "workspace_id") != Some(loaded.bundle.workspace_id.as_str())
    {
        invalid(
            report,
            "subject_opening",
            "proof.verify.subject.opening_invalid",
            commitment,
            None,
        );
    } else {
        report.valid("subject_opening");
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "release verification joins caller trust, producer key history, Statement subjects, and content closure"
)]
fn verify_release(
    loaded: &LoadedBundle,
    trust: &TrustPolicy,
    records: &[VerifiedAuthorityRecord],
    report: &mut Report,
) {
    let manifest_ref = loaded.bundle.entrypoints.target_release_manifest;
    if manifest_ref.artifact_kind != ArtifactKind::ReleaseV2 {
        invalid(
            report,
            "release_subjects",
            "proof.verify.release.requires_v2",
            Some(manifest_ref.digest),
            None,
        );
        return;
    }
    let Some(manifest) = loaded.artifacts.get(&manifest_ref) else {
        return;
    };
    let Some(envelope) = loaded
        .artifacts
        .get(&loaded.bundle.entrypoints.target_release_proof_envelope)
    else {
        return;
    };
    let max_envelope_bytes = usize::try_from(trust.limits.max_artifact_bytes)
        .unwrap_or(crate::model::MAX_ARTIFACT_BYTES);
    let peek = match parse_dsse_unverified(
        &envelope.bytes,
        trust.limits.max_json_depth as usize,
        max_envelope_bytes,
        max_envelope_bytes,
    ) {
        Ok(value) => value,
        Err(_) => {
            invalid(
                report,
                "release_signature",
                "proof.verify.release.envelope",
                None,
                None,
            );
            return;
        }
    };
    let key_id = peek
        .payload
        .pointer("/predicate/release/key_id")
        .and_then(Value::as_str);
    let trusted = key_id.and_then(|key_id| {
        trust
            .release
            .trusted_signers
            .iter()
            .find(|key| key.key_id == key_id)
    });
    let Some(trusted) = trusted else {
        invalid(
            report,
            "release_key_trust",
            "proof.verify.release.key_untrusted",
            None,
            None,
        );
        return;
    };
    let signer = parse_public_signer(&trusted.key_id, &trusted.public_key).ok();
    let Some(signer) = signer else {
        invalid(
            report,
            "release_key_trust",
            "proof.verify.release.key_untrusted",
            None,
            None,
        );
        return;
    };
    let verified = match verify_dsse(
        &envelope.bytes,
        ArtifactKind::ProofEnvelopeV1,
        &[IN_TOTO_PAYLOAD],
        &[signer],
        trust.limits.max_json_depth as usize,
        max_envelope_bytes,
        max_envelope_bytes,
    ) {
        Ok(value) => value,
        Err(_) => {
            invalid(
                report,
                "release_signature",
                "proof.verify.release.signature",
                None,
                None,
            );
            return;
        }
    };
    report.valid("release_signature");
    let statement = &verified.payload;
    if string(statement, "_type") != Some(IN_TOTO_STATEMENT)
        || statement
            .get("predicateType")
            .and_then(Value::as_str)
            .is_none_or(|predicate_type| {
                !trust
                    .release
                    .accepted_predicate_types
                    .iter()
                    .any(|accepted| accepted == predicate_type)
            })
    {
        invalid(
            report,
            "release_signature",
            "proof.verify.release.statement_profile",
            None,
            None,
        );
        return;
    }
    let predicate = statement.get("predicate").unwrap_or(&Value::Null);
    let release = predicate.get("release").unwrap_or(&Value::Null);
    let released_at = string(release, "released_at").and_then(parse_timestamp);
    if released_at.is_none_or(|at| !key_active_at(trusted, at, &trusted.key_id)) {
        invalid(
            report,
            "release_key_trust",
            "proof.verify.release.key_time",
            None,
            None,
        );
    }
    if !verify_release_key_evidence(loaded, trusted, key_id, released_at) {
        invalid(
            report,
            "release_key_trust",
            "proof.verify.release.producer_key",
            None,
            None,
        );
    }
    report.valid("release_key_trust");
    let release_id = string(release, "release_id");
    let release_subject_matches = statement
        .get("subject")
        .and_then(Value::as_array)
        .is_some_and(|subjects| {
            subjects.iter().any(|subject| {
                string(subject, "name")
                    == release_id
                        .map(|id| format!("proof:release:{id}"))
                        .as_deref()
                    && subject.pointer("/digest/blake3").and_then(Value::as_str)
                        == Some(manifest_ref.digest.hex().as_str())
            })
        });
    let edition_id = release
        .pointer("/edition/edition_id")
        .and_then(Value::as_str);
    let edition_digest = release
        .pointer("/edition/digest")
        .and_then(Value::as_str)
        .and_then(Digest::parse);
    let edition_subject_matches = statement
        .get("subject")
        .and_then(Value::as_array)
        .is_some_and(|subjects| {
            subjects.iter().any(|subject| {
                string(subject, "name")
                    == edition_id
                        .map(|id| format!("proof:edition:{id}"))
                        .as_deref()
                    && subject.pointer("/digest/blake3").and_then(Value::as_str)
                        == edition_digest.map(Digest::hex).as_deref()
            })
        });
    let release_fields_match = string(&manifest.value, "api_version")
        == Some("proof.dev/release/v2")
        && string(&manifest.value, "workspace_id") == string(predicate, "workspace_id")
        && string(&manifest.value, "key_id") == key_id
        && string(&manifest.value, "principal_id")
            == predicate
                .pointer("/authority/human_principal_id")
                .and_then(Value::as_str)
        && manifest.value.get("base_release") == release.get("base_release")
        && manifest.value.get("changeset_id") == release.get("changeset_id")
        && manifest.value.get("edition") == release.get("edition")
        && manifest.value.get("environment_id") == release.get("environment_id")
        && manifest.value.get("kind") == release.get("kind")
        && manifest.value.get("release_id") == release.get("release_id")
        && manifest.value.get("release_sequence") == release.get("release_sequence")
        && manifest.value.get("released_at") == release.get("released_at")
        && manifest.value.get("resource_intent_id") == release.get("resource_intent_id")
        && manifest.value.get("rollback_target_release_id")
            == release.get("rollback_target_release_id")
        && manifest.value.get("exact_delta_digest") == predicate.get("exact_delta_digest");
    let release_digest_matches = digest_field(release, "release_digest")
        == Some(manifest_ref.digest)
        && string(&manifest.value, "release_id") == release_id;
    let human_decision = predicate
        .pointer("/authority/authorization_decision_digest")
        .and_then(Value::as_str)
        .and_then(Digest::parse);
    if !release_subject_matches
        || !edition_subject_matches
        || !release_fields_match
        || !release_digest_matches
        || human_decision == Some(loaded.bundle.entrypoints.target_authorization_record_digest)
        || predicate
            .pointer("/authority/human_principal_id")
            .and_then(Value::as_str)
            .is_none()
    {
        invalid(
            report,
            "release_subjects",
            "proof.verify.release.subject",
            Some(manifest_ref.digest),
            None,
        );
    } else {
        report.valid("release_subjects");
    }
    report.verified_claims.release_id = release_id.map(str::to_owned);
    report.verified_claims.release_digest = Some(manifest_ref.digest);
    report.verified_claims.authorization_decision_digest = human_decision;

    let policy_profile = predicate
        .pointer("/authority/policy_profile")
        .and_then(Value::as_str);
    let environment_digest = digest_field(&manifest.value, "environment_config_digest");
    let environment_version = u64_field(&manifest.value, "environment_config_version");
    let environment_id = string(&manifest.value, "environment_id");
    let human_principal = predicate
        .pointer("/authority/human_principal_id")
        .and_then(Value::as_str);
    let accepted = trust.release.accepted_policy_profiles.iter().any(|policy| {
        Some(policy.policy_profile.as_str()) == policy_profile
            && Some(policy.environment_config_digest) == environment_digest
    });
    let exact_policy_decision = match human_decision
        .map(|digest| loaded.required_role_artifact(EvidenceRole::ReleasePolicyDecision, digest))
    {
        Some(RequiredArtifact::Available(artifact)) => Some(artifact),
        Some(RequiredArtifact::MissingRequiredExternal) => {
            incomplete(
                report,
                "policy",
                "proof.verify.release.policy_missing",
                human_decision,
                None,
            );
            return;
        }
        Some(RequiredArtifact::InvalidOrAbsent) | None => None,
    };
    let policy_decision_matches = exact_policy_decision.is_some_and(|artifact| {
        string(&artifact.value, "api_version")
            == Some("proof.dev/release-authorization-decision/v2")
            && artifact.value.get("allowed").and_then(Value::as_bool) == Some(true)
            && string(&artifact.value, "action") == Some("release.create")
            && string(&artifact.value, "workspace_id") == Some(loaded.bundle.workspace_id.as_str())
            && string(&artifact.value, "operating_principal_id") == human_principal
            && string(&artifact.value, "environment_id") == environment_id
            && u64_field(&artifact.value, "environment_config_version") == environment_version
            && digest_field(&artifact.value, "environment_config_digest") == environment_digest
            && string(&artifact.value, "policy_profile") == policy_profile
            && string(&artifact.value, "evaluated_at") == string(release, "released_at")
            && artifact.value.get("base_release") == release.get("base_release")
            && artifact.value.get("changeset_id") == release.get("changeset_id")
            && artifact.value.get("edition") == release.get("edition")
            && artifact.value.get("exact_delta_digest") == predicate.get("exact_delta_digest")
            && artifact.value.get("kind") == release.get("kind")
            && artifact.value.get("resource_intent_id") == release.get("resource_intent_id")
            && artifact.value.get("rollback_target_release_id")
                == release.get("rollback_target_release_id")
            && digest_field(&manifest.value, "authorization_decision_digest") == human_decision
    });
    let exact_environment = environment_digest.and_then(|digest| {
        loaded
            .bundle
            .artifacts
            .iter()
            .find(|descriptor| {
                descriptor.role == EvidenceRole::EnvironmentConfig
                    && descriptor.artifact.digest == digest
            })
            .and_then(|descriptor| loaded.artifacts.get(&descriptor.artifact))
    });
    let environment_matches = exact_environment.is_some_and(|artifact| {
        string(&artifact.value, "api_version") == Some("proof.dev/environment/v1")
            && string(&artifact.value, "workspace_id") == Some(loaded.bundle.workspace_id.as_str())
            && string(&artifact.value, "environment_id") == environment_id
            && u64_field(&artifact.value, "config_version") == environment_version
            && string(&artifact.value, "policy_profile") == policy_profile
            && string(&artifact.value, "required_approval")
                == exact_policy_decision
                    .and_then(|decision| string(&decision.value, "required_approval"))
    });
    let policy_bundle_digest =
        exact_environment.and_then(|artifact| digest_field(&artifact.value, "policy_digest"));
    let policy_bundle_matches = policy_bundle_digest.is_some_and(|digest| {
        loaded.bundle.artifacts.iter().any(|descriptor| {
            descriptor.role == EvidenceRole::EnvironmentPolicyBundle
                && descriptor.artifact.digest == digest
                && loaded.artifacts.contains_key(&descriptor.artifact)
        })
    });
    if !accepted || !policy_decision_matches || !environment_matches || !policy_bundle_matches {
        invalid(
            report,
            "policy",
            "proof.verify.release.policy",
            Some(manifest_ref.digest),
            None,
        );
    }

    let exact_delta_digest = digest_field(predicate, "exact_delta_digest");
    let delta_artifact = exact_delta_digest.and_then(|digest| {
        loaded
            .bundle
            .artifacts
            .iter()
            .find(|descriptor| {
                descriptor.role == EvidenceRole::EditionDelta
                    && descriptor.artifact.digest == digest
            })
            .and_then(|descriptor| {
                loaded
                    .artifacts
                    .get(&descriptor.artifact)
                    .map(|artifact| (descriptor.artifact, artifact))
            })
    });
    let delta_matches = predicate
        .get("exact_delta")
        .zip(delta_artifact)
        .is_some_and(|(embedded, (reference, artifact))| {
            canonical_bytes(embedded)
                .ok()
                .map(|bytes| domain_digest(ArtifactKind::ReleaseV2, &bytes))
                == exact_delta_digest
                && exact_delta_digest == Some(reference.digest)
                && embedded == &artifact.value
        });
    let content_matches = delta_artifact.is_some_and(|(_, artifact)| {
        verify_release_content_closure(
            loaded,
            predicate,
            &manifest.value,
            &artifact.value,
            exact_policy_decision.map(|artifact| &artifact.value),
            exact_environment.map(|artifact| &artifact.value),
            report,
        )
    });
    if delta_matches && content_matches {
        report.valid("content_delta");
    } else if !delta_matches {
        invalid(
            report,
            "content_delta",
            "proof.verify.release.delta",
            Some(manifest_ref.digest),
            None,
        );
    }
    let target = records.iter().find(|record| {
        record.digest == loaded.bundle.entrypoints.target_authorization_record_digest
    });
    let target_operation = target
        .and_then(|record| record.value.pointer("/operation/name"))
        .and_then(Value::as_str);
    if !content_matches || target_operation != Some("release.create") {
        invalid(
            report,
            "approval",
            "proof.verify.release.content_approval",
            Some(manifest_ref.digest),
            None,
        );
    } else {
        report.valid("approval");
    }
}

fn verify_release_content_closure(
    loaded: &LoadedBundle,
    predicate: &Value,
    manifest: &Value,
    delta: &Value,
    policy_decision: Option<&Value>,
    environment: Option<&Value>,
    report: &mut Report,
) -> bool {
    verify_release_content_closure_v1(
        loaded,
        predicate,
        manifest,
        delta,
        policy_decision,
        environment,
        report,
    )
}

fn verify_release_content_closure_v1(
    loaded: &LoadedBundle,
    predicate: &Value,
    manifest: &Value,
    delta: &Value,
    policy_decision: Option<&Value>,
    environment: Option<&Value>,
    report: &mut Report,
) -> bool {
    let result = match string(manifest, "kind") {
        Some("promotion") => verify_promotion_content(
            loaded,
            predicate,
            manifest,
            delta,
            policy_decision,
            environment,
        ),
        Some("rollback") => verify_rollback_content(loaded, predicate, manifest, delta),
        _ => Err("proof.verify.content.release_kind"),
    };
    match result {
        Ok(()) => true,
        Err(code) => {
            invalid(
                report,
                "content_delta",
                code,
                loaded
                    .bundle
                    .entrypoints
                    .target_release_manifest
                    .digest
                    .into(),
                None,
            );
            false
        }
    }
}

type ContentVerificationResult = Result<(), &'static str>;

fn verify_content_references<'a>(
    loaded: &'a LoadedBundle,
    predicate: &Value,
    manifest: &Value,
    delta: &Value,
) -> Result<
    (
        &'a LoadedArtifact,
        &'a LoadedArtifact,
        &'a LoadedArtifact,
        &'a LoadedArtifact,
    ),
    &'static str,
> {
    if string(delta, "api_version") != Some("proof.dev/edition-delta/v2")
        || delta.pointer("/target/edition") != predicate.pointer("/release/edition")
        || delta.pointer("/target/state") != predicate.get("state")
        || predicate.pointer("/content_evidence/base/edition") != delta.pointer("/base/edition")
        || predicate.pointer("/content_evidence/base/known_state") != delta.pointer("/base/state")
        || predicate.pointer("/content_evidence/base/release")
            != predicate.pointer("/release/base_release")
    {
        return Err("proof.verify.content.references");
    }
    let target_edition_ref = delta
        .pointer("/target/edition")
        .ok_or("proof.verify.content.references")?;
    let base_edition_ref = delta
        .pointer("/base/edition")
        .ok_or("proof.verify.content.references")?;
    let target_state_ref = delta
        .pointer("/target/state")
        .ok_or("proof.verify.content.references")?;
    let base_state_ref = delta
        .pointer("/base/state")
        .ok_or("proof.verify.content.references")?;
    let target_edition = exact_role_artifact(
        loaded,
        EvidenceRole::Edition,
        reference_digest(target_edition_ref),
    )
    .ok_or("proof.verify.content.target_edition")?;
    let base_edition = exact_role_artifact(
        loaded,
        EvidenceRole::Edition,
        reference_digest(base_edition_ref),
    )
    .ok_or("proof.verify.content.base_edition")?;
    let target_state = exact_role_artifact(
        loaded,
        EvidenceRole::KnownState,
        reference_digest(target_state_ref),
    )
    .ok_or("proof.verify.content.target_state")?;
    let base_state = exact_role_artifact(
        loaded,
        EvidenceRole::KnownState,
        reference_digest(base_state_ref),
    )
    .ok_or("proof.verify.content.base_state")?;
    if string(&target_edition.value, "api_version") != Some("proof.dev/edition/v2")
        || string(&target_edition.value, "edition_id") != string(target_edition_ref, "edition_id")
        || string(&target_state.value, "api_version") != string(target_state_ref, "api_version")
        || u64_field(&target_state.value, "authoritative_sequence")
            != u64_field(target_state_ref, "authoritative_sequence")
        || string(&base_state.value, "api_version") != string(base_state_ref, "api_version")
        || u64_field(&base_state.value, "authoritative_sequence")
            != u64_field(base_state_ref, "authoritative_sequence")
        || string(&target_state.value, "workspace_id") != Some(loaded.bundle.workspace_id.as_str())
        || string(&base_state.value, "workspace_id") != Some(loaded.bundle.workspace_id.as_str())
        || string(&target_edition.value, "workspace_id")
            != Some(loaded.bundle.workspace_id.as_str())
        || target_edition.value.get("state") != Some(target_state_ref)
        || target_edition.value.get("base_edition") != Some(base_edition_ref)
        || u64_field(&target_edition.value, "authoritative_sequence")
            != u64_field(target_state_ref, "authoritative_sequence")
    {
        return Err("proof.verify.content.reference_artifacts");
    }
    let base_edition_matches = match string(base_edition_ref, "api_version") {
        Some("proof.dev/edition/v1") => {
            string(&base_edition.value, "api_version") == Some("proof.dev/edition/v1")
                && digest_field(&base_edition.value, "state_digest")
                    == reference_digest(base_state_ref)
                && u64_field(&base_edition.value, "authoritative_sequence")
                    == u64_field(base_state_ref, "authoritative_sequence")
        }
        Some("proof.dev/edition/v2") => {
            string(&base_edition.value, "api_version") == Some("proof.dev/edition/v2")
                && base_edition.value.get("state") == Some(base_state_ref)
                && string(&base_edition.value, "edition_id")
                    == string(base_edition_ref, "edition_id")
        }
        _ => false,
    };
    if !base_edition_matches {
        return Err("proof.verify.content.base_edition");
    }
    let predecessor = target_state.value.get("previous_state");
    if predecessor != Some(base_state_ref)
        || u64_field(target_state_ref, "authoritative_sequence")
            != u64_field(base_state_ref, "authoritative_sequence").and_then(|sequence| {
                delta
                    .get("renditions")
                    .and_then(Value::as_array)
                    .and_then(|renditions| u64::try_from(renditions.len()).ok())
                    .and_then(|count| sequence.checked_add(count))
            })
        || target_edition.value.get("schemas") != target_state.value.get("schemas")
        || target_edition.value.get("objects") != target_state.value.get("objects")
        || target_edition.value.get("renditions") != target_state.value.get("renditions")
    {
        return Err("proof.verify.content.state_transition");
    }
    verify_delta_against_states(delta, &base_state.value, &target_state.value)?;
    if manifest.get("edition") != Some(target_edition_ref)
        || predicate.pointer("/content_evidence/resulting_state") != Some(target_state_ref)
    {
        return Err("proof.verify.content.release_state");
    }
    Ok((target_edition, base_edition, target_state, base_state))
}

fn verify_promotion_content(
    loaded: &LoadedBundle,
    predicate: &Value,
    manifest: &Value,
    delta: &Value,
    policy_decision: Option<&Value>,
    environment: Option<&Value>,
) -> ContentVerificationResult {
    verify_promotion_predecessor(loaded, manifest, delta)?;
    let (target_edition, _, _, _) = verify_content_references(loaded, predicate, manifest, delta)?;
    if !delta
        .get("schemas")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
        || !delta
            .get("objects")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        return Err("proof.verify.content.hitchhike");
    }
    let content = predicate
        .get("content_evidence")
        .ok_or("proof.verify.content.evidence")?;
    let changeset = content
        .get("changeset")
        .ok_or("proof.verify.content.changeset")?;
    if manifest.get("changeset_id") != changeset.get("changeset_id")
        || manifest.get("resource_intent_id") != content.pointer("/resource_intent/intent_id")
        || target_edition.value.pointer("/changeset/changeset_id") != changeset.get("changeset_id")
        || target_edition.value.pointer("/changeset/proposal_digest")
            != changeset.get("proposal_digest")
        || target_edition
            .value
            .pointer("/changeset/effective_leaf_digest")
            != changeset.get("effective_leaf_digest")
        || target_edition
            .value
            .pointer("/changeset/sealed_changeset_digest")
            != changeset.get("sealed_changeset_digest")
    {
        return Err("proof.verify.content.changeset_reference");
    }
    let proposal = exact_role_artifact(
        loaded,
        EvidenceRole::ChangeSet,
        digest_field(changeset, "proposal_digest"),
    )
    .ok_or("proof.verify.content.changeset_proposal")?;
    verify_intent_and_context(loaded, content, &proposal.value)?;
    let final_validation =
        verify_changeset_and_validations(loaded, content, changeset, &proposal.value)?;
    if target_edition
        .value
        .pointer("/changeset/validation_results_digest")
        != final_validation.get("results_digest")
    {
        return Err("proof.verify.content.validation_head");
    }
    verify_rendition_closure(loaded, content, delta, changeset, &proposal.value)?;
    verify_submission_and_approval(
        loaded,
        changeset,
        final_validation,
        policy_decision,
        environment,
        predicate,
    )
}

fn verify_promotion_predecessor(
    loaded: &LoadedBundle,
    manifest: &Value,
    delta: &Value,
) -> ContentVerificationResult {
    if string(manifest, "kind") != Some("promotion")
        || !manifest
            .get("rollback_target_release_id")
            .is_some_and(Value::is_null)
    {
        return Err("proof.verify.content.promotion_shape");
    }
    let base_reference = manifest
        .get("base_release")
        .filter(|value| !value.is_null())
        .ok_or("proof.verify.content.release_predecessor")?;
    let base = exact_role_artifact(
        loaded,
        EvidenceRole::ReleaseManifest,
        reference_digest(base_reference),
    )
    .ok_or("proof.verify.content.release_predecessor")?;
    let base_api =
        string(base_reference, "api_version").ok_or("proof.verify.content.release_predecessor")?;
    if !matches!(base_api, "proof.dev/release/v1" | "proof.dev/release/v2")
        || string(&base.value, "api_version") != Some(base_api)
        || base.value.get("release_id") != base_reference.get("release_id")
        || string(&base.value, "workspace_id") != string(manifest, "workspace_id")
        || string(&base.value, "environment_id") != string(manifest, "environment_id")
    {
        return Err("proof.verify.content.release_predecessor");
    }
    let edition_matches = match base_api {
        "proof.dev/release/v1" => {
            base.value.get("edition_id") == delta.pointer("/base/edition/edition_id")
                && digest_field(&base.value, "edition_digest")
                    == delta
                        .pointer("/base/edition/digest")
                        .and_then(Value::as_str)
                        .and_then(Digest::parse)
        }
        "proof.dev/release/v2" => base.value.get("edition") == delta.pointer("/base/edition"),
        _ => false,
    };
    let base_sequence = u64_field(&base.value, "release_sequence")
        .ok_or("proof.verify.content.release_predecessor")?;
    let chronology = string(&base.value, "released_at")
        .and_then(parse_timestamp)
        .zip(string(manifest, "released_at").and_then(parse_timestamp))
        .is_some_and(|(base, target)| base <= target);
    if !edition_matches
        || u64_field(manifest, "release_sequence")
            .is_none_or(|target_sequence| target_sequence <= base_sequence)
        || !chronology
    {
        return Err("proof.verify.content.release_predecessor");
    }
    Ok(())
}

fn verify_rollback_content(
    loaded: &LoadedBundle,
    predicate: &Value,
    manifest: &Value,
    delta: &Value,
) -> ContentVerificationResult {
    verify_rollback_content_references(loaded, predicate, manifest, delta)?;
    if !predicate
        .get("content_evidence")
        .is_some_and(Value::is_null)
        || !manifest.get("changeset_id").is_some_and(Value::is_null)
        || !manifest
            .get("resource_intent_id")
            .is_some_and(Value::is_null)
    {
        return Err("proof.verify.content.rollback_shape");
    }
    let rollback_id = string(manifest, "rollback_target_release_id")
        .ok_or("proof.verify.content.rollback_target")?;
    let target_edition = manifest
        .get("edition")
        .ok_or("proof.verify.content.rollback_target")?;
    let mut target_releases =
        artifacts_for_role(loaded, EvidenceRole::ReleaseManifest).filter(|artifact| {
            string(&artifact.value, "release_id") == Some(rollback_id)
                && release_selects_edition(&artifact.value, target_edition)
                && string(&artifact.value, "environment_id") == string(manifest, "environment_id")
        });
    let target_release = target_releases
        .next()
        .filter(|_| target_releases.next().is_none())
        .ok_or("proof.verify.content.rollback_target")?;
    let target_sequence = u64_field(&target_release.value, "release_sequence")
        .ok_or("proof.verify.content.rollback_target")?;
    let base_reference = manifest
        .get("base_release")
        .ok_or("proof.verify.content.rollback_ancestry")?;
    let base_release = exact_role_artifact(
        loaded,
        EvidenceRole::ReleaseManifest,
        reference_digest(base_reference),
    )
    .filter(|artifact| {
        artifact.value.get("release_id") == base_reference.get("release_id")
            && delta
                .pointer("/base/edition")
                .is_some_and(|edition| release_selects_edition(&artifact.value, edition))
            && string(&artifact.value, "environment_id") == string(manifest, "environment_id")
    })
    .ok_or("proof.verify.content.rollback_ancestry")?;
    let base_sequence = u64_field(&base_release.value, "release_sequence")
        .ok_or("proof.verify.content.rollback_ancestry")?;
    let chronology = string(&target_release.value, "released_at")
        .and_then(parse_timestamp)
        .zip(string(&base_release.value, "released_at").and_then(parse_timestamp))
        .zip(string(manifest, "released_at").and_then(parse_timestamp))
        .is_some_and(|((target, base), current)| target <= base && base <= current);
    if u64_field(manifest, "release_sequence")
        .is_none_or(|current_sequence| current_sequence <= base_sequence)
        || target_sequence >= base_sequence
        || !chronology
        || !release_is_on_predecessor_chain(loaded, manifest, rollback_id)
    {
        return Err("proof.verify.content.rollback_ancestry");
    }
    Ok(())
}

fn release_selects_edition(release: &Value, edition: &Value) -> bool {
    match string(release, "api_version") {
        Some("proof.dev/release/v1") => {
            release.get("edition_id") == edition.get("edition_id")
                && release.get("edition_digest") == edition.get("digest")
        }
        Some("proof.dev/release/v2") => release.get("edition") == Some(edition),
        _ => false,
    }
}

fn verify_rollback_content_references(
    loaded: &LoadedBundle,
    predicate: &Value,
    manifest: &Value,
    delta: &Value,
) -> ContentVerificationResult {
    if string(delta, "api_version") != Some("proof.dev/edition-delta/v2")
        || delta.pointer("/target/edition") != predicate.pointer("/release/edition")
        || delta.pointer("/target/state") != predicate.get("state")
        || manifest.get("edition") != delta.pointer("/target/edition")
    {
        return Err("proof.verify.content.rollback_references");
    }
    let base_edition_ref = delta
        .pointer("/base/edition")
        .ok_or("proof.verify.content.rollback_references")?;
    let base_state_ref = delta
        .pointer("/base/state")
        .ok_or("proof.verify.content.rollback_references")?;
    let target_edition_ref = delta
        .pointer("/target/edition")
        .ok_or("proof.verify.content.rollback_references")?;
    let target_state_ref = delta
        .pointer("/target/state")
        .ok_or("proof.verify.content.rollback_references")?;
    let base_edition = exact_role_artifact(
        loaded,
        EvidenceRole::Edition,
        reference_digest(base_edition_ref),
    )
    .ok_or("proof.verify.content.base_edition")?;
    let base_state = exact_role_artifact(
        loaded,
        EvidenceRole::KnownState,
        reference_digest(base_state_ref),
    )
    .ok_or("proof.verify.content.base_state")?;
    let target_edition = exact_role_artifact(
        loaded,
        EvidenceRole::Edition,
        reference_digest(target_edition_ref),
    )
    .ok_or("proof.verify.content.target_edition")?;
    let target_state = exact_role_artifact(
        loaded,
        EvidenceRole::KnownState,
        reference_digest(target_state_ref),
    )
    .ok_or("proof.verify.content.target_state")?;
    if !versioned_edition_matches(
        &base_edition.value,
        base_edition_ref,
        base_state_ref,
        &loaded.bundle.workspace_id,
    ) || !versioned_edition_matches(
        &target_edition.value,
        target_edition_ref,
        target_state_ref,
        &loaded.bundle.workspace_id,
    ) || !versioned_state_matches(
        &base_state.value,
        base_state_ref,
        &loaded.bundle.workspace_id,
    ) || !versioned_state_matches(
        &target_state.value,
        target_state_ref,
        &loaded.bundle.workspace_id,
    ) {
        return Err("proof.verify.content.rollback_reference_artifacts");
    }
    verify_delta_against_states(delta, &base_state.value, &target_state.value)
}

fn versioned_state_matches(value: &Value, reference: &Value, workspace_id: &str) -> bool {
    matches!(
        string(reference, "api_version"),
        Some("proof.dev/known-state/v1" | "proof.dev/known-state/v2")
    ) && value.get("api_version") == reference.get("api_version")
        && u64_field(value, "authoritative_sequence")
            == u64_field(reference, "authoritative_sequence")
        && string(value, "workspace_id") == Some(workspace_id)
}

fn versioned_edition_matches(
    value: &Value,
    reference: &Value,
    state_reference: &Value,
    workspace_id: &str,
) -> bool {
    if string(value, "workspace_id") != Some(workspace_id) {
        return false;
    }
    match string(reference, "api_version") {
        Some("proof.dev/edition/v1") => {
            string(value, "api_version") == Some("proof.dev/edition/v1")
                && digest_field(value, "state_digest") == reference_digest(state_reference)
                && u64_field(value, "authoritative_sequence")
                    == u64_field(state_reference, "authoritative_sequence")
        }
        Some("proof.dev/edition/v2") => {
            string(value, "api_version") == Some("proof.dev/edition/v2")
                && value.get("state") == Some(state_reference)
                && value.get("edition_id") == reference.get("edition_id")
        }
        _ => false,
    }
}

fn exact_role_artifact(
    loaded: &LoadedBundle,
    role: EvidenceRole,
    digest: Option<Digest>,
) -> Option<&LoadedArtifact> {
    let digest = digest?;
    let mut matches = loaded
        .bundle
        .artifacts
        .iter()
        .filter(|descriptor| descriptor.role == role && descriptor.artifact.digest == digest)
        .filter_map(|descriptor| loaded.artifacts.get(&descriptor.artifact));
    let artifact = matches.next()?;
    matches.next().is_none().then_some(artifact)
}

fn reference_digest(reference: &Value) -> Option<Digest> {
    digest_field(reference, "digest")
}

fn array_field<'a>(value: &'a Value, field: &str) -> Option<&'a [Value]> {
    match value.get(field) {
        Some(Value::Array(values)) => Some(values),
        None => Some(&[]),
        _ => None,
    }
}

fn ordered_value_map<F>(values: &[Value], key: F) -> Option<BTreeMap<String, Value>>
where
    F: Fn(&Value) -> Option<String>,
{
    let mut output = BTreeMap::new();
    let mut previous: Option<String> = None;
    for value in values {
        let key = key(value)?;
        if previous.as_ref().is_some_and(|previous| previous >= &key)
            || output.insert(key.clone(), value.clone()).is_some()
        {
            return None;
        }
        previous = Some(key);
    }
    Some(output)
}

fn schema_key(value: &Value) -> Option<String> {
    Some(format!(
        "{}\0{:010}",
        string(value, "schema_id")?,
        u64_field(value, "schema_version")?
    ))
}

fn object_key(value: &Value) -> Option<String> {
    string(value, "object_id").map(str::to_owned)
}

fn rendition_key(value: &Value) -> Option<String> {
    Some(format!(
        "{}\0{}",
        string(value, "object_id")?,
        string(value, "locale")?
    ))
}

fn verify_delta_against_states(
    delta: &Value,
    base_state: &Value,
    target_state: &Value,
) -> ContentVerificationResult {
    let base_schemas = ordered_value_map(
        array_field(base_state, "schemas").ok_or("proof.verify.content.state_schema")?,
        schema_key,
    )
    .ok_or("proof.verify.content.state_schema")?;
    let target_schemas = ordered_value_map(
        array_field(target_state, "schemas").ok_or("proof.verify.content.state_schema")?,
        schema_key,
    )
    .ok_or("proof.verify.content.state_schema")?;
    let base_objects = ordered_value_map(
        array_field(base_state, "objects").ok_or("proof.verify.content.state_object")?,
        object_key,
    )
    .ok_or("proof.verify.content.state_object")?;
    let target_objects = ordered_value_map(
        array_field(target_state, "objects").ok_or("proof.verify.content.state_object")?,
        object_key,
    )
    .ok_or("proof.verify.content.state_object")?;
    let base_renditions = ordered_value_map(
        array_field(base_state, "renditions").ok_or("proof.verify.content.state_rendition")?,
        rendition_key,
    )
    .ok_or("proof.verify.content.state_rendition")?;
    let target_renditions = ordered_value_map(
        array_field(target_state, "renditions").ok_or("proof.verify.content.state_rendition")?,
        rendition_key,
    )
    .ok_or("proof.verify.content.state_rendition")?;

    let schema_keys = base_schemas
        .keys()
        .chain(target_schemas.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_schemas = schema_keys
        .into_iter()
        .filter_map(|key| {
            let before = base_schemas.get(&key);
            let after = target_schemas.get(&key);
            (before != after).then(|| {
                let selected = before.or(after)?;
                Some(json!({
                    "after": after.and_then(|value| string(value, "document_digest")),
                    "before": before.and_then(|value| string(value, "document_digest")),
                    "schema_id": string(selected, "schema_id"),
                    "schema_version": u64_field(selected, "schema_version"),
                }))
            })?
        })
        .collect::<Vec<_>>();
    let object_keys = base_objects
        .keys()
        .chain(target_objects.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_objects = object_keys
        .into_iter()
        .filter_map(|key| {
            let before = base_objects.get(&key);
            let after = target_objects.get(&key);
            (before != after).then(|| {
                json!({
                    "after": after,
                    "before": before,
                    "object_id": key,
                })
            })
        })
        .collect::<Vec<_>>();
    let rendition_keys = base_renditions
        .keys()
        .chain(target_renditions.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_renditions = rendition_keys
        .into_iter()
        .filter_map(|key| {
            let before = base_renditions.get(&key);
            let after = target_renditions.get(&key);
            (before != after).then(|| {
                let selected = before.or(after)?;
                Some(json!({
                    "after": after,
                    "before": before,
                    "locale": string(selected, "locale"),
                    "object_id": string(selected, "object_id"),
                }))
            })?
        })
        .collect::<Vec<_>>();
    if delta.get("schemas") != Some(&Value::Array(expected_schemas))
        || delta.get("objects") != Some(&Value::Array(expected_objects))
        || delta.get("renditions") != Some(&Value::Array(expected_renditions))
    {
        return Err("proof.verify.content.delta_state_mismatch");
    }
    Ok(())
}

fn verify_intent_and_context(
    loaded: &LoadedBundle,
    content: &Value,
    proposal: &Value,
) -> ContentVerificationResult {
    let release = loaded
        .artifacts
        .get(&loaded.bundle.entrypoints.target_release_manifest)
        .ok_or("proof.verify.content.release_state")?;
    let intent_evidence = content
        .get("resource_intent")
        .ok_or("proof.verify.content.intent")?;
    let intent = exact_role_artifact(
        loaded,
        EvidenceRole::ResourceIntent,
        digest_field(intent_evidence, "digest"),
    )
    .ok_or("proof.verify.content.intent")?;
    if string(&intent.value, "api_version") != Some("proof.dev/content-resource-intent/v1")
        || string(&intent.value, "workspace_id") != Some(loaded.bundle.workspace_id.as_str())
        || intent.value.get("intent_id") != intent_evidence.get("intent_id")
        || intent.value.get("targets") != intent_evidence.get("targets")
        || intent.value.get("base") != content.get("base")
        || intent.value.get("intent_id") != proposal.get("resource_intent_id")
        || intent.value.get("environment_id") != release.value.get("environment_id")
        || intent.value.get("issued_by_principal_id") != release.value.get("principal_id")
        || digest_field(proposal, "resource_intent_digest")
            != digest_field(intent_evidence, "digest")
    {
        return Err("proof.verify.content.intent_cross_link");
    }
    let context_digest =
        digest_field(proposal, "context_pack_digest").ok_or("proof.verify.content.context")?;
    let context_pack = exact_role_artifact(loaded, EvidenceRole::ContextPack, Some(context_digest))
        .ok_or("proof.verify.content.context")?;
    let policy_digest =
        digest_field(&context_pack.value, "policy_digest").ok_or("proof.verify.content.context")?;
    let context_policy = exact_role_artifact(
        loaded,
        EvidenceRole::ContextPolicyBundle,
        Some(policy_digest),
    )
    .ok_or("proof.verify.content.context_policy")?;
    if string(&context_pack.value, "api_version") != Some("proof.dev/context-pack/v2")
        || string(&context_pack.value, "workspace_id") != Some(loaded.bundle.workspace_id.as_str())
        || context_pack.value.get("context_pack_id") != proposal.get("context_pack_id")
        || context_pack.value.get("resource_intent") != Some(&intent.value)
        || digest_field(&context_pack.value, "resource_intent_digest")
            != digest_field(intent_evidence, "digest")
        || context_pack.value.get("policy") != Some(&context_policy.value)
        || context_pack.value.get("principal_id") != intent.value.get("issued_by_principal_id")
        || digest_field(content, "context_pack_digest") != Some(context_digest)
    {
        return Err("proof.verify.content.context_cross_link");
    }
    let freshness = string(&intent.value, "issued_at")
        .and_then(parse_timestamp)
        .zip(string(&context_pack.value, "created_at").and_then(parse_timestamp))
        .zip(string(&context_pack.value, "expires_at").and_then(parse_timestamp))
        .zip(string(&release.value, "released_at").and_then(parse_timestamp))
        .is_some_and(|(((issued, created), expires), released)| {
            issued <= created && created <= released && released < expires
        });
    let budget = context_pack
        .value
        .pointer("/limits/max_bytes")
        .and_then(Value::as_u64)
        .is_some_and(|maximum| {
            u64::try_from(context_pack.bytes.len()).is_ok_and(|size| size <= maximum)
        });
    if !freshness || !budget {
        return Err("proof.verify.content.context_freshness");
    }
    let targets = intent
        .value
        .get("targets")
        .and_then(Value::as_array)
        .ok_or("proof.verify.content.intent_targets")?;
    let resources = context_pack
        .value
        .get("resources")
        .and_then(Value::as_array)
        .ok_or("proof.verify.content.context_resources")?;
    let target_keys = targets
        .iter()
        .map(|target| {
            Some((
                string(target, "object_id")?,
                string(target, "schema_id")?,
                string(target, "locale")?,
            ))
        })
        .collect::<Option<Vec<_>>>()
        .ok_or("proof.verify.content.intent_targets")?;
    let resource_keys = resources
        .iter()
        .map(|resource| {
            Some((
                string(resource, "object_id")?,
                resource.pointer("/schema/schema_id")?.as_str()?,
                string(resource, "locale")?,
            ))
        })
        .collect::<Option<Vec<_>>>()
        .ok_or("proof.verify.content.context_resources")?;
    if target_keys != resource_keys {
        return Err("proof.verify.content.context_resources");
    }
    let maximum_objects = context_pack
        .value
        .pointer("/limits/max_objects")
        .and_then(Value::as_u64)
        .ok_or("proof.verify.content.context_resources")?;
    let maximum_edits = context_pack
        .value
        .pointer("/limits/max_edits")
        .and_then(Value::as_u64)
        .ok_or("proof.verify.content.context_resources")?;
    let unique_objects = target_keys
        .iter()
        .map(|(object, _, _)| *object)
        .collect::<BTreeSet<_>>()
        .len();
    let edits = proposal
        .get("edits")
        .and_then(Value::as_array)
        .ok_or("proof.verify.content.edits")?;
    if u64::try_from(unique_objects).map_or(true, |count| count > maximum_objects)
        || u64::try_from(resources.len()).map_or(true, |count| count > maximum_edits)
        || u64::try_from(edits.len()).map_or(true, |count| count > maximum_edits)
        || !context_policy_is_legal(resources, &context_policy.value)
        || !verify_context_resources(loaded, content, resources, edits)
    {
        return Err("proof.verify.content.context_resources");
    }
    Ok(())
}

fn verify_context_resources(
    loaded: &LoadedBundle,
    content: &Value,
    resources: &[Value],
    edits: &[Value],
) -> bool {
    let Some(base_state) = exact_role_artifact(
        loaded,
        EvidenceRole::KnownState,
        content
            .pointer("/base/known_state/digest")
            .and_then(Value::as_str)
            .and_then(Digest::parse),
    ) else {
        return false;
    };
    resources.iter().all(|resource| {
        let Some(schema_closure) = resource.get("schema") else {
            return false;
        };
        let Some(schema_artifact) = exact_role_artifact(
            loaded,
            EvidenceRole::Schema,
            digest_field(schema_closure, "document_digest"),
        ) else {
            return false;
        };
        let Some(source_closure) = resource.get("source") else {
            return false;
        };
        let Some(source_artifact) = exact_role_artifact(
            loaded,
            EvidenceRole::Object,
            digest_field(source_closure, "digest"),
        ) else {
            return false;
        };
        // SchemaVersionV1 evidence is the canonical raw JSON Schema document.
        // Schema identity and version are carried by the signed context/state
        // references, not by an invented wrapper around these bytes.
        let schema_matches = schema_artifact.value == schema_closure["document"]
            && schema::document_accepts(&schema_artifact.value, &source_artifact.value["content"])
            && localizable_pointers_are_exact(&schema_artifact.value, schema_closure);
        let source_matches = object_keys_exact(
            &source_artifact.value,
            &[
                "api_version",
                "content",
                "lifecycle_state",
                "object_id",
                "relationships",
                "revision",
                "schema_id",
                "schema_version",
            ],
        ) && string(&source_artifact.value, "api_version")
            == Some("proof.dev/object-revision/v1")
            && source_artifact.value.get("content") == source_closure.get("content")
            && source_artifact.value.get("revision") == source_closure.get("revision")
            && source_artifact.value.get("object_id") == resource.get("object_id")
            && source_artifact.value.get("schema_id") == schema_closure.get("schema_id")
            && source_artifact.value.get("schema_version") == schema_closure.get("schema_version")
            && string(&source_artifact.value, "lifecycle_state") == Some("active")
            && schema::document_accepts(&schema_artifact.value, &source_artifact.value["content"]);
        let base_object_matches = base_state
            .value
            .get("objects")
            .and_then(Value::as_array)
            .is_some_and(|objects| {
                objects.iter().any(|object| {
                    object.get("object_id") == resource.get("object_id")
                        && object.get("object_digest") == source_closure.get("digest")
                        && object.get("revision") == source_closure.get("revision")
                        && object.get("schema_id") == schema_closure.get("schema_id")
                        && object.get("schema_version") == schema_closure.get("schema_version")
                })
            });
        let base_schema_matches = base_state
            .value
            .get("schemas")
            .and_then(Value::as_array)
            .is_some_and(|schemas| {
                schemas.iter().any(|schema| {
                    schema.get("schema_id") == schema_closure.get("schema_id")
                        && schema.get("schema_version") == schema_closure.get("schema_version")
                        && schema.get("document_digest") == schema_closure.get("document_digest")
                })
            });
        let target_matches = resource.get("target").is_some_and(|target| {
            match target.get("absent").and_then(Value::as_bool) {
                Some(true) => {
                    target.get("authoritative_sequence")
                        == base_state.value.get("authoritative_sequence")
                        && base_state
                            .value
                            .get("renditions")
                            .and_then(Value::as_array)
                            .is_none_or(|renditions| {
                                !renditions.iter().any(|rendition| {
                                    rendition.get("object_id") == resource.get("object_id")
                                        && rendition.get("locale") == resource.get("locale")
                                })
                            })
                }
                Some(false) => digest_field(target, "digest").is_some_and(|digest| {
                    exact_role_artifact(loaded, EvidenceRole::LocaleRevision, Some(digest))
                        .is_some_and(|artifact| {
                            target.get("manifest") == Some(&artifact.value)
                                && target.get("revision") == artifact.value.get("revision")
                                && artifact.value.get("object_id") == resource.get("object_id")
                                && artifact.value.get("locale") == resource.get("locale")
                                && base_state
                                    .value
                                    .get("renditions")
                                    .and_then(Value::as_array)
                                    .is_some_and(|renditions| {
                                        renditions.iter().any(|rendition| {
                                            rendition.get("object_id") == resource.get("object_id")
                                                && rendition.get("locale") == resource.get("locale")
                                                && rendition.get("rendition_digest")
                                                    == target.get("digest")
                                                && rendition.get("revision")
                                                    == target.get("revision")
                                                && rendition.get("schema_id")
                                                    == artifact.value.get("schema_id")
                                                && rendition.get("schema_version")
                                                    == artifact.value.get("schema_version")
                                                && rendition.get("source_object_digest")
                                                    == artifact.value.get("source_object_digest")
                                        })
                                    })
                        })
                }),
                None => false,
            }
        });
        let edits_match = edits
            .iter()
            .filter(|edit| {
                edit.get("object_id") == resource.get("object_id")
                    && edit.get("locale") == resource.get("locale")
            })
            .all(|edit| {
                edit.pointer("/expected_source/digest") == source_closure.get("digest")
                    && edit.pointer("/expected_source/revision") == source_closure.get("revision")
                    && edit.pointer("/expected_source/schema_id") == schema_closure.get("schema_id")
                    && edit.pointer("/expected_source/schema_version")
                        == schema_closure.get("schema_version")
                    && schema::document_accepts(
                        &schema_artifact.value,
                        edit.get("content").unwrap_or(&Value::Null),
                    )
                    && edit_content_is_localized_only(
                        &source_artifact.value["content"],
                        edit.get("content").unwrap_or(&Value::Null),
                        schema_closure
                            .get("localizable_pointers")
                            .and_then(Value::as_array)
                            .map_or(&[], Vec::as_slice),
                    )
            });
        schema_matches
            && source_matches
            && base_object_matches
            && base_schema_matches
            && target_matches
            && edits_match
    })
}

fn localizable_pointers_are_exact(document: &Value, schema_closure: &Value) -> bool {
    let Some(document_pointers) = document
        .get("x-proof-localizable")
        .and_then(Value::as_array)
    else {
        return false;
    };
    let Some(closure_pointers) = schema_closure
        .get("localizable_pointers")
        .and_then(Value::as_array)
    else {
        return false;
    };
    if document_pointers.is_empty() || document_pointers != closure_pointers {
        return false;
    }
    let Some(parsed) = document_pointers
        .iter()
        .map(|pointer| parse_json_pointer(pointer.as_str()?))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    document_pointers.windows(2).all(|pair| {
        pair[0]
            .as_str()
            .zip(pair[1].as_str())
            .is_some_and(|(left, right)| left < right)
    }) && parsed.iter().enumerate().all(|(index, left)| {
        schema_pointer_is_localizable(document, left)
            && parsed
                .iter()
                .skip(index + 1)
                .all(|right| !pointer_is_prefix(left, right) && !pointer_is_prefix(right, left))
    })
}

fn parse_json_pointer(pointer: &str) -> Option<Vec<String>> {
    if pointer.is_empty() || !pointer.starts_with('/') {
        return None;
    }
    pointer[1..]
        .split('/')
        .map(|raw| {
            let mut decoded = String::new();
            let mut characters = raw.chars();
            while let Some(character) = characters.next() {
                if character != '~' {
                    decoded.push(character);
                    continue;
                }
                match characters.next()? {
                    '0' => decoded.push('~'),
                    '1' => decoded.push('/'),
                    _ => return None,
                }
            }
            Some(decoded)
        })
        .collect()
}

fn pointer_is_prefix(left: &[String], right: &[String]) -> bool {
    left.len() <= right.len() && left.iter().zip(right).all(|(left, right)| left == right)
}

fn context_policy_is_legal(resources: &[Value], policy: &Value) -> bool {
    let Some(rules) = policy.get("rules").and_then(Value::as_array) else {
        return false;
    };
    let mut previous: Option<(&str, &str)> = None;
    for rule in rules {
        let Some(locale) = string(rule, "locale") else {
            return false;
        };
        let Some(pointer) = string(rule, "pointer") else {
            return false;
        };
        let Some(values) = rule.get("disallowed_values").and_then(Value::as_array) else {
            return false;
        };
        if values.is_empty()
            || !values.windows(2).all(|pair| {
                pair[0]
                    .as_str()
                    .zip(pair[1].as_str())
                    .is_some_and(|(left, right)| left < right)
            })
            || previous.is_some_and(|previous| previous >= (locale, pointer))
        {
            return false;
        }
        previous = Some((locale, pointer));
        let mut matching_resources = resources
            .iter()
            .filter(|resource| string(resource, "locale") == Some(locale));
        if !matching_resources.any(|resource| {
            resource
                .pointer("/schema/localizable_pointers")
                .and_then(Value::as_array)
                .is_some_and(|pointers| pointers.contains(&Value::String(pointer.to_owned())))
        }) || resources
            .iter()
            .filter(|resource| string(resource, "locale") == Some(locale))
            .any(|resource| {
                resource
                    .pointer("/schema/localizable_pointers")
                    .and_then(Value::as_array)
                    .is_none_or(|pointers| !pointers.contains(&Value::String(pointer.to_owned())))
            })
        {
            return false;
        }
    }
    true
}

fn schema_pointer_is_localizable(document: &Value, segments: &[String]) -> bool {
    let mut schema = document;
    for segment in segments {
        let Some(next) = schema
            .get("properties")
            .and_then(|properties| properties.get(segment))
        else {
            return false;
        };
        schema = next;
    }
    string(schema, "type") == Some("string")
}

fn edit_content_is_localized_only(source: &Value, edited: &Value, pointers: &[Value]) -> bool {
    let allowed = pointers
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    fn compare(source: &Value, edited: &Value, pointer: &str, allowed: &BTreeSet<&str>) -> bool {
        if allowed.contains(pointer) {
            return true;
        }
        match (source, edited) {
            (Value::Object(source), Value::Object(edited)) => {
                source.len() == edited.len()
                    && source.iter().all(|(key, value)| {
                        let escaped = key.replace('~', "~0").replace('/', "~1");
                        let child = format!("{pointer}/{escaped}");
                        edited
                            .get(key)
                            .is_some_and(|edited| compare(value, edited, &child, allowed))
                    })
            }
            _ => source == edited,
        }
    }
    compare(source, edited, "", &allowed)
}

fn release_is_on_predecessor_chain(
    loaded: &LoadedBundle,
    target: &Value,
    sought_release_id: &str,
) -> bool {
    let Some(initial) = target.get("base_release") else {
        return false;
    };
    let Some(mut current) = loaded
        .bundle
        .artifacts
        .iter()
        .find(|descriptor| {
            descriptor.role == EvidenceRole::ReleaseManifest
                && Some(descriptor.artifact.digest) == reference_digest(initial)
        })
        .map(|descriptor| descriptor.artifact)
    else {
        return false;
    };
    let mut expected_id = string(initial, "release_id").map(str::to_owned);
    let mut expected_api = string(initial, "api_version").map(str::to_owned);
    let mut later_sequence = u64_field(target, "release_sequence");
    let mut later_time = string(target, "released_at").and_then(parse_timestamp);
    let environment = string(target, "environment_id");
    let workspace = string(target, "workspace_id");
    let mut visited = BTreeSet::new();
    loop {
        let Some(artifact) = loaded.artifacts.get(&current) else {
            return false;
        };
        let Some(release_id) = string(&artifact.value, "release_id") else {
            return false;
        };
        let released_at = string(&artifact.value, "released_at").and_then(parse_timestamp);
        if !visited.insert(release_id.to_owned())
            || expected_id.as_deref() != Some(release_id)
            || expected_api.as_deref() != string(&artifact.value, "api_version")
            || u64_field(&artifact.value, "release_sequence")
                .zip(later_sequence)
                .is_none_or(|(earlier, later)| earlier >= later)
            || string(&artifact.value, "environment_id") != environment
            || string(&artifact.value, "workspace_id") != workspace
            || released_at
                .zip(later_time)
                .is_none_or(|(earlier, later)| earlier > later)
        {
            return false;
        }
        if release_id == sought_release_id {
            return true;
        }
        later_time = released_at;
        later_sequence = u64_field(&artifact.value, "release_sequence");
        match string(&artifact.value, "api_version") {
            Some("proof.dev/release/v2") => {
                let Some(reference) = artifact.value.get("base_release") else {
                    return false;
                };
                let Some(next) = loaded.bundle.artifacts.iter().find(|descriptor| {
                    descriptor.role == EvidenceRole::ReleaseManifest
                        && Some(descriptor.artifact.digest) == reference_digest(reference)
                }) else {
                    return false;
                };
                current = next.artifact;
                expected_id = string(reference, "release_id").map(str::to_owned);
                expected_api = string(reference, "api_version").map(str::to_owned);
            }
            Some("proof.dev/release/v1") => {
                let Some(previous_id) = string(&artifact.value, "previous_release_id") else {
                    return false;
                };
                let mut matches = loaded.bundle.artifacts.iter().filter(|descriptor| {
                    descriptor.role == EvidenceRole::ReleaseManifest
                        && loaded
                            .artifacts
                            .get(&descriptor.artifact)
                            .is_some_and(|candidate| {
                                string(&candidate.value, "release_id") == Some(previous_id)
                            })
                });
                let Some(next) = matches.next() else {
                    return false;
                };
                if matches.next().is_some() {
                    return false;
                }
                current = next.artifact;
                expected_id = Some(previous_id.to_owned());
                expected_api = loaded
                    .artifacts
                    .get(&current)
                    .and_then(|candidate| string(&candidate.value, "api_version"))
                    .map(str::to_owned);
            }
            _ => return false,
        }
    }
}

fn verify_changeset_and_validations<'a>(
    loaded: &LoadedBundle,
    content: &'a Value,
    changeset: &Value,
    proposal: &Value,
) -> Result<&'a Value, &'static str> {
    let edits = proposal
        .get("edits")
        .and_then(Value::as_array)
        .filter(|edits| !edits.is_empty() && edits.len() <= 100)
        .ok_or("proof.verify.content.edits")?;
    if string(proposal, "api_version") != Some("proof.dev/changeset/v2")
        || string(proposal, "workspace_id") != Some(loaded.bundle.workspace_id.as_str())
        || proposal.get("changeset_id") != changeset.get("changeset_id")
    {
        return Err("proof.verify.content.changeset_proposal");
    }
    verify_edit_lineage(loaded, edits, content, proposal)?;
    let final_snapshot = proposal_snapshot(proposal, edits)?;
    if Some(final_snapshot.proposal_digest) != digest_field(changeset, "proposal_digest")
        || Some(final_snapshot.effective_digest) != digest_field(changeset, "effective_leaf_digest")
        || proposal.get("effective_leaves") != Some(&final_snapshot.leaves)
    {
        return Err("proof.verify.content.proposal_reconstruction");
    }
    let effective_batch = exact_role_artifact(
        loaded,
        EvidenceRole::Edit,
        Some(final_snapshot.effective_digest),
    )
    .ok_or("proof.verify.content.effective_edits")?;
    if effective_batch.value != final_snapshot.batch {
        return Err("proof.verify.content.effective_edits");
    }
    let validations = content
        .get("validations")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= 100)
        .ok_or("proof.verify.content.validations")?;
    let maximum_validation_attempts = exact_role_artifact(
        loaded,
        EvidenceRole::ContextPack,
        digest_field(proposal, "context_pack_digest"),
    )
    .and_then(|context| {
        context
            .value
            .pointer("/limits/max_validation_attempts")
            .and_then(Value::as_u64)
    })
    .ok_or("proof.verify.content.validations")?;
    if u64::try_from(validations.len()).map_or(true, |count| count > maximum_validation_attempts) {
        return Err("proof.verify.content.validations");
    }
    let mut previous_results = None;
    let mut previous_prefix = 0_usize;
    let mut invalid_results = BTreeMap::<Digest, (usize, Value)>::new();
    for (index, evidence) in validations.iter().enumerate() {
        let results_digest = digest_field(evidence, "results_digest")
            .ok_or("proof.verify.content.validation_digest")?;
        let validation = exact_role_artifact(
            loaded,
            EvidenceRole::ValidationAttempt,
            Some(results_digest),
        )
        .ok_or("proof.verify.content.validation_artifact")?;
        let valid = evidence
            .get("valid")
            .and_then(Value::as_bool)
            .ok_or("proof.verify.content.validation_shape")?;
        if u64_field(evidence, "attempt") != Some(index as u64 + 1)
            || u64_field(&validation.value, "attempt") != Some(index as u64 + 1)
            || validation.value.get("changeset_id") != changeset.get("changeset_id")
            || digest_field(&validation.value, "previous_validation_result_digest")
                != previous_results
            || validation.value.get("previous_validation_result_digest")
                != evidence.get("previous_validation_result_digest")
            || validation.value.get("proposal_digest") != evidence.get("proposal_digest")
            || validation.value.get("valid") != Some(&Value::Bool(valid))
            || string(&validation.value, "api_version") != Some("proof.dev/validation-results/v2")
            || string(&validation.value, "validator") != Some("proof/localized-content/1")
            || digest_field(&validation.value, "context_pack_digest")
                != digest_field(proposal, "context_pack_digest")
        {
            return Err("proof.verify.content.validation_shape");
        }
        let matching_prefixes = (previous_prefix.max(1)..=edits.len())
            .filter_map(|length| {
                let snapshot = proposal_snapshot(proposal, &edits[..length]).ok()?;
                (Some(snapshot.proposal_digest) == digest_field(evidence, "proposal_digest")
                    && Some(snapshot.effective_digest)
                        == digest_field(&validation.value, "effective_leaf_digest"))
                .then_some(length)
            })
            .collect::<Vec<_>>();
        if matching_prefixes.len() != 1 {
            return Err("proof.verify.content.validation_proposal");
        }
        let prefix = matching_prefixes[0];
        let findings = validation
            .value
            .get("findings")
            .and_then(Value::as_array)
            .ok_or("proof.verify.content.validation_findings")?;
        if valid != findings.is_empty()
            || !validation_policy_is_exact(loaded, proposal, &edits[..prefix], &validation.value)
        {
            return Err("proof.verify.content.validation_findings");
        }
        if !valid {
            invalid_results.insert(results_digest, (prefix, validation.value.clone()));
        }
        previous_prefix = prefix;
        previous_results = Some(results_digest);
    }
    let final_validation = validations
        .last()
        .ok_or("proof.verify.content.validations")?;
    if final_validation.get("valid") != Some(&Value::Bool(true))
        || previous_prefix != edits.len()
        || digest_field(final_validation, "proposal_digest")
            != digest_field(changeset, "proposal_digest")
    {
        return Err("proof.verify.content.validation_head");
    }
    verify_repair_edges(proposal, edits, &invalid_results)?;
    let final_digest = digest_field(final_validation, "results_digest")
        .ok_or("proof.verify.content.validation_head")?;
    let sealed = exact_role_artifact(
        loaded,
        EvidenceRole::ChangeSet,
        digest_field(changeset, "sealed_changeset_digest"),
    )
    .ok_or("proof.verify.content.seal")?;
    if string(&sealed.value, "api_version") != Some("proof.dev/changeset-seal/v2")
        || digest_field(&sealed.value, "proposal_digest")
            != digest_field(changeset, "proposal_digest")
        || digest_field(&sealed.value, "validation_results_digest") != Some(final_digest)
    {
        return Err("proof.verify.content.seal");
    }
    Ok(final_validation)
}

fn validation_policy_is_exact(
    loaded: &LoadedBundle,
    proposal: &Value,
    edits: &[Value],
    validation: &Value,
) -> bool {
    let Some(context) = exact_role_artifact(
        loaded,
        EvidenceRole::ContextPack,
        digest_field(proposal, "context_pack_digest"),
    ) else {
        return false;
    };
    let Some(policy) = exact_role_artifact(
        loaded,
        EvidenceRole::ContextPolicyBundle,
        digest_field(&context.value, "policy_digest"),
    ) else {
        return false;
    };
    if validation.get("policy_digest") != context.value.get("policy_digest")
        || context.value.get("policy") != Some(&policy.value)
        || string(&policy.value, "api_version") != Some("proof.dev/localized-content-policy/v1")
    {
        return false;
    }
    let Some(resources) = context.value.get("resources").and_then(Value::as_array) else {
        return false;
    };
    let mut expected_schema_digests = resources
        .iter()
        .filter_map(|resource| {
            let schema = resource.get("schema")?;
            Some(json!({
                "document_digest": schema.get("document_digest"),
                "schema_id": schema.get("schema_id"),
                "schema_version": schema.get("schema_version"),
            }))
        })
        .collect::<Vec<_>>();
    expected_schema_digests.sort_by_key(|schema| {
        format!(
            "{}\0{:020}",
            string(schema, "schema_id").unwrap_or_default(),
            u64_field(schema, "schema_version").unwrap_or_default(),
        )
    });
    expected_schema_digests.dedup();
    if validation.get("schema_digests") != Some(&Value::Array(expected_schema_digests)) {
        return false;
    }
    let Some(rules) = policy.value.get("rules").and_then(Value::as_array) else {
        return false;
    };
    let mut active = BTreeMap::<String, &Value>::new();
    for edit in edits {
        let Some(key) = rendition_key(edit) else {
            return false;
        };
        active.insert(key, edit);
    }
    let mut expected_findings = Vec::new();
    for edit in active.values() {
        for rule in rules {
            if edit.get("locale") != rule.get("locale") {
                continue;
            }
            let Some(pointer) = string(rule, "pointer") else {
                return false;
            };
            let Some(value) = edit
                .get("content")
                .and_then(|content| content.pointer(pointer))
            else {
                continue;
            };
            let prohibited = rule
                .get("disallowed_values")
                .and_then(Value::as_array)
                .is_some_and(|values| values.contains(value));
            if prohibited {
                expected_findings.push(json!({
                    "code": "proof.validation.prohibited_legal_claim",
                    "edit_id": edit.get("edit_id"),
                    "locale": edit.get("locale"),
                    "object_id": edit.get("object_id"),
                    "pointer": pointer,
                    "policy_digest": context.value.get("policy_digest"),
                    "severity": "error",
                    "validator": "proof/localized-content/1",
                }));
            }
        }
    }
    validation.get("findings") == Some(&Value::Array(expected_findings.clone()))
        && validation.get("valid") == Some(&Value::Bool(expected_findings.is_empty()))
}

struct ProposalSnapshot {
    proposal_digest: Digest,
    effective_digest: Digest,
    batch: Value,
    leaves: Value,
}

fn proposal_snapshot(proposal: &Value, edits: &[Value]) -> Result<ProposalSnapshot, &'static str> {
    let mut active = BTreeMap::<String, &Value>::new();
    for edit in edits {
        active.insert(
            rendition_key(edit).ok_or("proof.verify.content.edit_shape")?,
            edit,
        );
    }
    let effective = active.values().copied().cloned().collect::<Vec<_>>();
    let batch = json!({
        "api_version": "proof.dev/edit-batch/v2",
        "edits": effective,
    });
    let batch_bytes = canonical_bytes(&batch).map_err(|_| "proof.verify.content.edit_batch")?;
    let effective_digest = domain_digest(ArtifactKind::EditBatchV2, &batch_bytes);
    let leaves = Value::Array(
        active
            .values()
            .map(|edit| {
                let bytes =
                    canonical_bytes(*edit).map_err(|_| "proof.verify.content.edit_shape")?;
                Ok(json!({
                    "edit_digest": domain_digest(ArtifactKind::EditV2, &bytes),
                    "edit_id": edit.get("edit_id"),
                    "locale": edit.get("locale"),
                    "object_id": edit.get("object_id"),
                }))
            })
            .collect::<Result<Vec<_>, &'static str>>()?,
    );
    let mut reconstructed = proposal.clone();
    let object = reconstructed
        .as_object_mut()
        .ok_or("proof.verify.content.changeset_proposal")?;
    object.insert("edits".to_owned(), Value::Array(edits.to_vec()));
    object.insert(
        "effective_leaf_digest".to_owned(),
        Value::String(effective_digest.to_string()),
    );
    object.insert("effective_leaves".to_owned(), leaves.clone());
    let bytes =
        canonical_bytes(&reconstructed).map_err(|_| "proof.verify.content.changeset_proposal")?;
    Ok(ProposalSnapshot {
        proposal_digest: domain_digest(ArtifactKind::ChangeSetV2, &bytes),
        effective_digest,
        batch,
        leaves,
    })
}

fn verify_edit_lineage(
    loaded: &LoadedBundle,
    edits: &[Value],
    content: &Value,
    proposal: &Value,
) -> ContentVerificationResult {
    let mut active = BTreeMap::<String, &str>::new();
    let mut ids = BTreeSet::new();
    for edit in edits {
        let id = string(edit, "edit_id").ok_or("proof.verify.content.edit_shape")?;
        let key = rendition_key(edit).ok_or("proof.verify.content.edit_shape")?;
        let prior = active.get(&key).copied();
        let supersedes = edit.get("supersedes_edit_id").and_then(Value::as_str);
        let repair = digest_field(edit, "repair_of_validation_result_digest");
        let bytes = canonical_bytes(edit).map_err(|_| "proof.verify.content.edit_shape")?;
        let digest = domain_digest(ArtifactKind::EditV2, &bytes);
        let artifact = exact_role_artifact(loaded, EvidenceRole::Edit, Some(digest))
            .ok_or("proof.verify.content.edit_artifact")?;
        if string(edit, "api_version") != Some("proof.dev/edit/v2")
            || string(edit, "kind") != Some("object.locale.put")
            || !ids.insert(id.to_owned())
            || artifact.value != *edit
            || match prior {
                None => supersedes.is_some() || repair.is_some(),
                Some(prior) => supersedes != Some(prior) || repair.is_none(),
            }
        {
            return Err("proof.verify.content.edit_lineage");
        }
        active.insert(key, id);
    }
    let target_keys = content
        .pointer("/resource_intent/targets")
        .and_then(Value::as_array)
        .ok_or("proof.verify.content.intent_targets")?
        .iter()
        .map(rendition_key)
        .collect::<Option<BTreeSet<_>>>()
        .ok_or("proof.verify.content.intent_targets")?;
    if active.keys().cloned().collect::<BTreeSet<_>>() != target_keys
        || proposal.get("base_state") != content.pointer("/base/known_state")
    {
        return Err("proof.verify.content.edit_targets");
    }
    Ok(())
}

fn verify_repair_edges(
    proposal: &Value,
    edits: &[Value],
    invalid_results: &BTreeMap<Digest, (usize, Value)>,
) -> ContentVerificationResult {
    for (index, edit) in edits.iter().enumerate() {
        let Some(repair_digest) = digest_field(edit, "repair_of_validation_result_digest") else {
            continue;
        };
        let (validated_prefix, validation) = invalid_results
            .get(&repair_digest)
            .ok_or("proof.verify.content.repair_evidence")?;
        if *validated_prefix != index
            || Some(proposal_snapshot(proposal, &edits[..index])?.proposal_digest)
                != digest_field(validation, "proposal_digest")
        {
            return Err("proof.verify.content.repair_evidence");
        }
        let superseded =
            string(edit, "supersedes_edit_id").ok_or("proof.verify.content.repair_evidence")?;
        let finding_matches = validation
            .get("findings")
            .and_then(Value::as_array)
            .is_some_and(|findings| {
                findings.iter().any(|finding| {
                    string(finding, "edit_id") == Some(superseded)
                        && finding.get("object_id") == edit.get("object_id")
                        && finding.get("locale") == edit.get("locale")
                        && string(finding, "severity") == Some("error")
                })
            });
        if !finding_matches {
            return Err("proof.verify.content.repair_evidence");
        }
    }
    if invalid_results.keys().any(|digest| {
        !edits
            .iter()
            .any(|edit| digest_field(edit, "repair_of_validation_result_digest") == Some(*digest))
    }) {
        return Err("proof.verify.content.unrepaired_validation");
    }
    Ok(())
}

fn verify_rendition_closure(
    loaded: &LoadedBundle,
    content: &Value,
    delta: &Value,
    changeset: &Value,
    proposal: &Value,
) -> ContentVerificationResult {
    let delta_renditions = ordered_value_map(
        delta
            .get("renditions")
            .and_then(Value::as_array)
            .ok_or("proof.verify.content.renditions")?,
        rendition_key,
    )
    .ok_or("proof.verify.content.renditions")?;
    let evidence_renditions = ordered_value_map(
        content
            .get("renditions")
            .and_then(Value::as_array)
            .ok_or("proof.verify.content.renditions")?,
        rendition_key,
    )
    .ok_or("proof.verify.content.renditions")?;
    let edits = proposal
        .get("edits")
        .and_then(Value::as_array)
        .ok_or("proof.verify.content.edits")?;
    let mut active_edits = BTreeMap::new();
    for edit in edits {
        active_edits.insert(
            rendition_key(edit).ok_or("proof.verify.content.edit_shape")?,
            edit,
        );
    }
    if delta_renditions.len() != evidence_renditions.len()
        || delta_renditions.len() != active_edits.len()
        || delta_renditions.keys().ne(evidence_renditions.keys())
        || delta_renditions.keys().ne(active_edits.keys())
    {
        return Err("proof.verify.content.rendition_targets");
    }
    let target_state = exact_role_artifact(
        loaded,
        EvidenceRole::KnownState,
        delta
            .pointer("/target/state/digest")
            .and_then(Value::as_str)
            .and_then(Digest::parse),
    )
    .ok_or("proof.verify.content.target_state")?;
    let base_sequence = delta
        .pointer("/base/state/authoritative_sequence")
        .and_then(Value::as_u64)
        .ok_or("proof.verify.content.rendition_sequence")?;
    for (index, (key, change)) in delta_renditions.iter().enumerate() {
        let after = change
            .get("after")
            .filter(|value| !value.is_null())
            .ok_or("proof.verify.content.rendition_removal")?;
        let before = change.get("before").filter(|value| !value.is_null());
        let evidence = evidence_renditions
            .get(key)
            .ok_or("proof.verify.content.rendition_evidence")?;
        let edit = active_edits
            .get(key)
            .copied()
            .ok_or("proof.verify.content.rendition_edit")?;
        let rendition_digest = digest_field(after, "rendition_digest")
            .ok_or("proof.verify.content.rendition_digest")?;
        let revision =
            exact_role_artifact(loaded, EvidenceRole::LocaleRevision, Some(rendition_digest))
                .ok_or("proof.verify.content.rendition_artifact")?;
        let before_digest = before.and_then(|value| digest_field(value, "rendition_digest"));
        let before_revision = before.and_then(|value| u64_field(value, "revision"));
        let expected_target = edit.get("expected_target").filter(|value| !value.is_null());
        if evidence.get("rendition_digest") != after.get("rendition_digest")
            || evidence.get("edit_id") != edit.get("edit_id")
            || evidence.get("object_id") != after.get("object_id")
            || evidence.get("locale") != after.get("locale")
            || evidence.get("schema_id") != after.get("schema_id")
            || evidence.get("schema_version") != after.get("schema_version")
            || evidence.get("source_object_digest") != after.get("source_object_digest")
            || expected_target.and_then(|value| digest_field(value, "digest")) != before_digest
            || expected_target.and_then(|value| u64_field(value, "revision")) != before_revision
            || string(&revision.value, "api_version") != Some("proof.dev/object-locale-revision/v1")
            || string(&revision.value, "workspace_id") != Some(loaded.bundle.workspace_id.as_str())
            || revision.value.get("changeset_id") != changeset.get("changeset_id")
            || revision.value.get("edit_id") != edit.get("edit_id")
            || revision.value.get("object_id") != after.get("object_id")
            || revision.value.get("locale") != after.get("locale")
            || revision.value.get("revision") != after.get("revision")
            || revision.value.get("schema_id") != after.get("schema_id")
            || revision.value.get("schema_version") != after.get("schema_version")
            || revision.value.get("source_object_digest") != after.get("source_object_digest")
            || edit.pointer("/expected_source/digest") != after.get("source_object_digest")
            || edit.pointer("/expected_source/schema_id") != after.get("schema_id")
            || edit.pointer("/expected_source/schema_version") != after.get("schema_version")
            || digest_field(&revision.value, "previous_revision_digest") != before_digest
            || revision.value.get("content") != edit.get("content")
            || revision.value.get("source_object_revision")
                != edit.pointer("/expected_source/revision")
            || u64_field(&revision.value, "authoritative_sequence")
                != u64::try_from(index)
                    .ok()
                    .and_then(|index| base_sequence.checked_add(index + 1))
        {
            return Err("proof.verify.content.rendition_cross_link");
        }
        let source_digest = digest_field(after, "source_object_digest")
            .ok_or("proof.verify.content.source_object")?;
        let source = exact_role_artifact(loaded, EvidenceRole::Object, Some(source_digest))
            .ok_or("proof.verify.content.source_object")?;
        if source.value.get("object_id") != after.get("object_id")
            || source.value.get("revision") != revision.value.get("source_object_revision")
            || source.value.get("schema_id") != after.get("schema_id")
            || source.value.get("schema_version") != after.get("schema_version")
            || string(&source.value, "lifecycle_state") != Some("active")
        {
            return Err("proof.verify.content.source_object");
        }
        let schema_entry = target_state
            .value
            .get("schemas")
            .and_then(Value::as_array)
            .and_then(|schemas| {
                schemas.iter().find(|schema| {
                    schema.get("schema_id") == after.get("schema_id")
                        && schema.get("schema_version") == after.get("schema_version")
                })
            })
            .ok_or("proof.verify.content.schema")?;
        let schema = exact_role_artifact(
            loaded,
            EvidenceRole::Schema,
            digest_field(schema_entry, "document_digest"),
        );
        if schema.is_none_or(|schema| {
            !schema::document_accepts(
                &schema.value,
                revision.value.get("content").unwrap_or(&Value::Null),
            )
        }) {
            return Err("proof.verify.content.schema");
        }
    }
    Ok(())
}

fn verify_submission_and_approval(
    loaded: &LoadedBundle,
    changeset: &Value,
    final_validation: &Value,
    policy_decision: Option<&Value>,
    environment: Option<&Value>,
    predicate: &Value,
) -> ContentVerificationResult {
    let changeset_id = string(changeset, "changeset_id").ok_or("proof.verify.content.approval")?;
    let sealed = digest_field(changeset, "sealed_changeset_digest")
        .ok_or("proof.verify.content.approval")?;
    let validation =
        digest_field(final_validation, "results_digest").ok_or("proof.verify.content.approval")?;
    let signed_approval = loaded
        .artifacts
        .get(&loaded.bundle.entrypoints.target_localized_consequence)
        .and_then(|consequence| consequence.value.pointer("/closure/approval"))
        .filter(|approval| !approval.is_null())
        .ok_or("proof.verify.content.approval")?;
    let signed_approval_digest =
        digest_field(signed_approval, "effect_digest").ok_or("proof.verify.content.approval")?;
    let mut submissions = artifacts_for_role(loaded, EvidenceRole::Submission).filter(|artifact| {
        operation_effect_shape(&artifact.value, "changeset.submit/v2")
            && artifact
                .value
                .pointer("/result/changeset_id")
                .and_then(Value::as_str)
                == Some(changeset_id)
            && digest_path(&artifact.value, &["result", "sealed_changeset_digest"]) == Some(sealed)
            && digest_path(&artifact.value, &["result", "validation_results_digest"])
                == Some(validation)
            && artifact
                .value
                .pointer("/result/approval")
                .is_some_and(Value::is_null)
    });
    let submission = submissions
        .next()
        .filter(|_| submissions.next().is_none())
        .ok_or("proof.verify.content.submission")?;
    let required = environment
        .and_then(|value| string(value, "required_approval"))
        .filter(|required| {
            policy_decision.and_then(|value| string(value, "required_approval")) == Some(*required)
        })
        .ok_or("proof.verify.content.approval_policy")?;
    let mut approvals = artifacts_for_role(loaded, EvidenceRole::Approval).filter(|artifact| {
        operation_effect_shape(&artifact.value, "changeset.approve/v2")
            && domain_digest(ArtifactKind::OperationEffectV1, &artifact.bytes)
                == signed_approval_digest
            && artifact
                .value
                .pointer("/result/changeset_id")
                .and_then(Value::as_str)
                == Some(changeset_id)
            && artifact
                .value
                .pointer("/result/approval")
                .and_then(Value::as_str)
                == Some(required)
            && artifact.value.pointer("/result/principal_id") == signed_approval.get("principal_id")
            && artifact.value.pointer("/result/occurred_at") == signed_approval.get("approved_at")
            && artifact.value.pointer("/result/approval") == signed_approval.get("approval_name")
            && digest_path(&artifact.value, &["result", "sealed_changeset_digest"]) == Some(sealed)
            && digest_path(&artifact.value, &["result", "validation_results_digest"])
                == Some(validation)
    });
    let approval = approvals
        .next()
        .filter(|_| approvals.next().is_none())
        .ok_or("proof.verify.content.approval")?;
    let submitted_at = submission
        .value
        .pointer("/result/occurred_at")
        .and_then(Value::as_str)
        .and_then(parse_timestamp);
    let approved_at = approval
        .value
        .pointer("/result/occurred_at")
        .and_then(Value::as_str)
        .and_then(parse_timestamp);
    let released_at = predicate
        .pointer("/release/released_at")
        .and_then(Value::as_str)
        .and_then(parse_timestamp);
    if submitted_at
        .zip(approved_at)
        .zip(released_at)
        .is_none_or(|((submitted, approved), released)| submitted > approved || approved > released)
    {
        return Err("proof.verify.content.approval_time");
    }
    Ok(())
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

fn key_active_at(key: &TrustedKey, at: OffsetDateTime, key_id: &str) -> bool {
    key.key_id == key_id
        && parse_timestamp(&key.not_before).is_some_and(|start| start <= at)
        && key
            .not_after
            .as_deref()
            .and_then(parse_timestamp)
            .is_none_or(|end| at < end)
        && key
            .revoked_at
            .as_deref()
            .and_then(parse_timestamp)
            .is_none_or(|revoked| at < revoked)
}

fn parse_hex_key(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(output)
}

fn verify_release_key_evidence(
    loaded: &LoadedBundle,
    trusted: &TrustedKey,
    key_id: Option<&str>,
    released_at: Option<OffsetDateTime>,
) -> bool {
    let Some(key_id) = key_id else {
        return false;
    };
    let Some(released_at) = released_at else {
        return false;
    };
    let Some(caller) = parse_public_signer(&trusted.key_id, &trusted.public_key).ok() else {
        return false;
    };
    let all_keys = artifacts_for_role(loaded, EvidenceRole::ReleaseSigningKey)
        .map(|artifact| release_key_wrapper(artifact, &loaded.bundle.workspace_id))
        .collect::<Option<Vec<_>>>();
    let Some(all_keys) = all_keys else {
        return false;
    };
    let mut key_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    if all_keys.is_empty()
        || all_keys.iter().any(|(key_id, public_key, _)| {
            !key_ids.insert(*key_id) || !public_keys.insert(*public_key)
        })
    {
        return false;
    }
    let producer_keys = all_keys
        .iter()
        .filter(|(producer_key_id, _, _)| *producer_key_id == key_id)
        .collect::<Vec<_>>();
    let [(_, producer_public, not_before)] = producer_keys.as_slice() else {
        return false;
    };
    if *producer_public != caller.public_key || *not_before > released_at {
        return false;
    }
    let all_revocations = artifacts_for_role(loaded, EvidenceRole::ReleaseSigningKeyRevocation)
        .map(|artifact| release_key_revocation_wrapper(artifact, &loaded.bundle.workspace_id))
        .collect::<Option<Vec<_>>>();
    let Some(all_revocations) = all_revocations else {
        return false;
    };
    let mut revoked_key_ids = BTreeSet::new();
    if all_revocations
        .iter()
        .any(|(key_id, _)| !revoked_key_ids.insert(*key_id))
    {
        return false;
    }
    let revocations = all_revocations
        .iter()
        .filter(|(revoked_key_id, _)| *revoked_key_id == key_id)
        .collect::<Vec<_>>();
    let producer_revoked_at = match revocations.as_slice() {
        [] => None,
        [(_, revoked_at)] => Some(*revoked_at),
        _ => return false,
    };
    if producer_revoked_at.is_some_and(|revoked| released_at >= revoked) {
        return false;
    }
    let caller_revoked_at = trusted.revoked_at.as_deref().and_then(parse_timestamp);
    producer_revoked_at
        .zip(caller_revoked_at)
        .is_none_or(|(producer, caller)| producer == caller)
}

fn release_key_wrapper<'a>(
    artifact: &'a LoadedArtifact,
    workspace_id: &str,
) -> Option<(&'a str, [u8; 32], OffsetDateTime)> {
    let value = &artifact.value;
    let metadata = value.get("metadata")?;
    let metadata_digest = digest_field(value, "native_metadata_digest")?;
    let metadata_reproduces = canonical_bytes(metadata)
        .ok()
        .map(|bytes| domain_digest(ArtifactKind::PolicyBundleV1, &bytes))
        == Some(metadata_digest);
    let key_id = string(value, "key_id")?;
    let public_key = string(value, "public_key").and_then(parse_hex_key)?;
    let not_before = string(value, "not_before").and_then(parse_timestamp)?;
    let public_key_matches_id = key_id
        .strip_prefix("ed25519:")
        .is_some_and(|hex| hex == hex_key(public_key));
    (object_keys_exact(
        value,
        &[
            "algorithm",
            "api_version",
            "key_id",
            "metadata",
            "native_metadata_digest",
            "not_before",
            "public_key",
            "trust_profile",
            "workspace_id",
        ],
    ) && string(value, "api_version") == Some("proof.dev/release-signing-key/v1")
        && string(value, "workspace_id") == Some(workspace_id)
        && string(value, "algorithm") == Some("ed25519")
        && string(value, "trust_profile") == Some("proof.local/release-proof/v1")
        && public_key_matches_id
        && metadata_reproduces
        && object_keys_exact(
            metadata,
            &[
                "algorithm",
                "api_version",
                "key_id",
                "not_before",
                "public_key",
                "trust_profile",
            ],
        )
        && string(metadata, "api_version") == Some("proof.dev/signing-key-metadata/v1")
        && metadata.get("algorithm") == value.get("algorithm")
        && metadata.get("key_id") == value.get("key_id")
        && metadata.get("not_before") == value.get("not_before")
        && metadata.get("public_key") == value.get("public_key")
        && metadata.get("trust_profile") == value.get("trust_profile"))
    .then_some((key_id, public_key, not_before))
}

fn release_key_revocation_wrapper<'a>(
    artifact: &'a LoadedArtifact,
    workspace_id: &str,
) -> Option<(&'a str, OffsetDateTime)> {
    let value = &artifact.value;
    let native = value.get("native_revocation")?;
    let native_digest = digest_field(value, "native_revocation_digest")?;
    let native_reproduces = canonical_bytes(native)
        .ok()
        .map(|bytes| domain_digest(ArtifactKind::PolicyBundleV1, &bytes))
        == Some(native_digest);
    let key_id = string(value, "key_id")?;
    let revoked_at = string(value, "revoked_at").and_then(parse_timestamp)?;
    (object_keys_exact(
        value,
        &[
            "api_version",
            "key_id",
            "native_revocation",
            "native_revocation_digest",
            "reason",
            "revoked_at",
            "workspace_id",
        ],
    ) && string(value, "api_version") == Some("proof.dev/release-signing-key-revocation/v1")
        && string(value, "workspace_id") == Some(workspace_id)
        && string(value, "reason").is_some_and(|reason| !reason.is_empty())
        && native_reproduces
        && object_keys_exact(native, &["api_version", "key_id", "reason", "revoked_at"])
        && string(native, "api_version") == Some("proof.dev/signing-key-revocation/v1")
        && native.get("key_id") == value.get("key_id")
        && native.get("reason") == value.get("reason")
        && native.get("revoked_at") == value.get("revoked_at"))
    .then_some((key_id, revoked_at))
}

fn hex_key(bytes: [u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn record_time(value: &Value) -> Option<OffsetDateTime> {
    [
        "recorded_at",
        "issued_at",
        "revoked_at",
        "evaluated_at",
        "activated_at",
    ]
    .into_iter()
    .find_map(|field| string(value, field).and_then(parse_timestamp))
}

fn authority_record_shape_is_valid(value: &Value) -> bool {
    match string(value, "api_version") {
        Some("proof.dev/principal-status/v1") => {
            object_keys_exact(
                value,
                &[
                    "api_version",
                    "authority_sequence",
                    "previous_authority_record_digest",
                    "workspace_id",
                    "principal_id",
                    "principal_type",
                    "enabled",
                    "recorded_by_principal_id",
                    "recorded_at",
                ],
            ) && common_authority_fields_valid(value)
                && value.get("enabled").is_some_and(Value::is_boolean)
                && matches!(
                    string(value, "principal_type"),
                    Some("human" | "agent" | "service" | "system_component")
                )
                && string(value, "recorded_at")
                    .and_then(parse_timestamp)
                    .is_some()
        }
        Some("proof.dev/principal-binding/v1") => principal_binding_shape_is_valid(value),
        Some("proof.dev/principal-binding-revocation/v1") => revocation_shape_is_valid(
            value,
            &[
                "api_version",
                "authority_sequence",
                "previous_authority_record_digest",
                "workspace_id",
                "revocation_id",
                "binding_id",
                "revoked_by_principal_id",
                "revoked_at",
                "reason",
            ],
            &[
                "administrative",
                "compromise",
                "disablement",
                "recovery",
                "rotation",
            ],
        ),
        Some("proof.dev/delegation/v2") => delegation_shape_is_valid(value),
        Some("proof.dev/delegation-revocation/v1") => revocation_shape_is_valid(
            value,
            &[
                "api_version",
                "authority_sequence",
                "previous_authority_record_digest",
                "workspace_id",
                "revocation_id",
                "delegation_id",
                "revoked_by_principal_id",
                "revoked_at",
                "reason",
            ],
            &[
                "administrative",
                "compromise",
                "issuer_request",
                "scope_change",
            ],
        ),
        Some("proof.dev/authorization-decision/v2") => decision_shape_is_valid(value),
        Some("proof.dev/workspace-authority-root-transition/v1") => {
            root_transition_shape_is_valid(value)
        }
        _ => false,
    }
}

fn common_authority_fields_valid(value: &Value) -> bool {
    u64_field(value, "authority_sequence").is_some_and(|sequence| sequence > 0)
        && string(value, "workspace_id").is_some_and(|workspace| !workspace.is_empty())
        && optional_digest_field(value, "previous_authority_record_digest").is_some()
}

fn principal_binding_shape_is_valid(value: &Value) -> bool {
    let subject = value.get("authenticated_subject");
    let key_id = subject.and_then(|subject| string(subject, "subject"));
    let signer = key_id
        .zip(string(value, "public_key"))
        .and_then(|(key_id, public_key)| parse_public_signer(key_id, public_key).ok());
    let issued = string(value, "issued_at").and_then(parse_timestamp);
    let start = string(value, "not_before").and_then(parse_timestamp);
    let end = string(value, "expires_at").and_then(parse_timestamp);
    object_keys_exact(
        value,
        &[
            "algorithm",
            "api_version",
            "audience",
            "authenticated_subject",
            "authority_sequence",
            "binding_id",
            "enrollment_challenge_digest",
            "enrollment_envelope_digest",
            "expires_at",
            "issued_at",
            "issued_by_principal_id",
            "key_usage",
            "not_before",
            "previous_authority_record_digest",
            "principal_id",
            "principal_type",
            "public_key",
            "supersedes_binding_id",
            "workspace_id",
        ],
    ) && common_authority_fields_valid(value)
        && subject.is_some_and(|subject| {
            object_keys_exact(subject, &["api_version", "provider", "subject"])
                && string(subject, "api_version") == Some("proof.dev/authenticated-subject/v1")
                && string(subject, "provider") == Some("proof/local-ed25519")
        })
        && signer.is_some()
        && string(value, "algorithm") == Some("ed25519")
        && string(value, "key_usage") == Some("authenticated-command")
        && string(value, "principal_type") == Some("agent")
        && string(value, "audience")
            == string(value, "workspace_id")
                .map(|workspace| format!("proof://workspace/{workspace}"))
                .as_deref()
        && issued
            .zip(start)
            .zip(end)
            .is_some_and(|((issued, start), end)| issued <= start && start < end)
        && string(value, "supersedes_binding_id") != string(value, "binding_id")
        && digest_field(value, "enrollment_challenge_digest").is_some()
        && digest_field(value, "enrollment_envelope_digest").is_some()
}

fn revocation_shape_is_valid(value: &Value, keys: &[&str], accepted_reasons: &[&str]) -> bool {
    object_keys_exact(value, keys)
        && common_authority_fields_valid(value)
        && string(value, "revoked_at")
            .and_then(parse_timestamp)
            .is_some()
        && string(value, "reason").is_some_and(|reason| accepted_reasons.contains(&reason))
}

fn delegation_shape_is_valid(value: &Value) -> bool {
    let issued = string(value, "issued_at").and_then(parse_timestamp);
    let start = string(value, "not_before").and_then(parse_timestamp);
    let end = string(value, "expires_at").and_then(parse_timestamp);
    object_keys_exact(
        value,
        &[
            "actions",
            "api_version",
            "authority_sequence",
            "constraints",
            "delegation_id",
            "delegation_profile",
            "expires_at",
            "issued_at",
            "issuer_principal_id",
            "not_before",
            "previous_authority_record_digest",
            "recipient_principal_id",
            "scope",
            "workspace_id",
        ],
    ) && common_authority_fields_valid(value)
        && string(value, "delegation_profile") == Some("proof.local/authority/direct/v1")
        && string(value, "issuer_principal_id") != string(value, "recipient_principal_id")
        && issued
            .zip(start)
            .zip(end)
            .is_some_and(|((issued, start), end)| issued <= start && start < end)
        && sorted_unique_strings(value.get("actions"), 1, 12)
        && value.get("scope").is_some_and(|scope| {
            object_keys_exact(
                scope,
                &["environment_ids", "locales", "object_ids", "schema_ids"],
            ) && sorted_unique_strings(scope.get("environment_ids"), 0, 32)
                && sorted_unique_strings(scope.get("locales"), 0, 64)
                && sorted_unique_strings(scope.get("object_ids"), 0, 100)
                && sorted_unique_strings(scope.get("schema_ids"), 0, 100)
        })
        && value.get("constraints").is_some_and(|constraints| {
            object_keys_exact(
                constraints,
                &[
                    "allow_subdelegation",
                    "max_context_bytes",
                    "max_edits_per_changeset",
                    "max_objects",
                ],
            ) && constraints.get("allow_subdelegation") == Some(&Value::Bool(false))
                && u64_field(constraints, "max_objects")
                    .is_some_and(|value| (1..=100).contains(&value))
                && u64_field(constraints, "max_edits_per_changeset")
                    .is_some_and(|value| (1..=100).contains(&value))
                && u64_field(constraints, "max_context_bytes")
                    .is_some_and(|value| (1..=1_048_576).contains(&value))
        })
}

fn sorted_unique_strings(value: Option<&Value>, minimum: usize, maximum: usize) -> bool {
    value.and_then(Value::as_array).is_some_and(|values| {
        (minimum..=maximum).contains(&values.len())
            && values.iter().all(Value::is_string)
            && values
                .windows(2)
                .all(|pair| pair[0].as_str() < pair[1].as_str())
    })
}

fn decision_shape_is_valid(value: &Value) -> bool {
    let mut expected = BTreeSet::from([
        "actor_context_digest",
        "api_version",
        "audience",
        "authority_key_id",
        "authority_sequence",
        "binding",
        "command_digest",
        "command_envelope_digest",
        "decision",
        "delegation",
        "effective_constraints",
        "evaluated_at",
        "evaluated_authority_head",
        "operating_principal_id",
        "operation",
        "policy_bundle_digest",
        "policy_profile",
        "presentation_consumed",
        "presentation_id",
        "previous_authority_record_digest",
        "principal_state",
        "reason_code",
        "requested_action",
        "requested_resources",
        "requesting_principal_id",
        "requesting_subject_commitment",
        "workspace_id",
    ]);
    if value.get("localized_consequence_commitment").is_some() {
        expected.insert("localized_consequence_commitment");
    }
    let keys_match = value.as_object().is_some_and(|object| {
        object.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected
    });
    let operation = value.get("operation");
    let operation_valid = operation.is_some_and(|operation| {
        object_keys_exact(operation, &["name", "version"])
            && operation_action(string(operation, "name"), string(operation, "version"))
                == string(value, "requested_action")
    });
    let head = value.get("evaluated_authority_head");
    let binding = value.get("binding");
    let delegation = value.get("delegation");
    let principal_state = value.get("principal_state");
    let requested = value.get("requested_resources");
    let constraints = value.get("effective_constraints");
    let decision = string(value, "decision");
    let reason = value.get("reason_code");
    let decision_valid = match (decision, reason) {
        (Some("allow"), Some(Value::Null)) => true,
        (Some("deny"), Some(Value::String(reason))) => authorization_denial_reason_is_valid(reason),
        _ => false,
    };
    let head_sequence = head.and_then(|head| u64_field(head, "sequence"));
    let binding_sequence = binding.and_then(|binding| u64_field(binding, "authority_sequence"));
    let binding_revocation = binding.and_then(|binding| binding.get("revocation_record_digest"));
    let delegation_resolution = delegation.and_then(|delegation| string(delegation, "resolution"));
    let delegation_record = delegation.and_then(|delegation| delegation.get("record_digest"));
    let delegation_revocation =
        delegation.and_then(|delegation| delegation.get("revocation_record_digest"));
    let principal_enabled = principal_state.is_some_and(|state| {
        state.get("operating_principal_enabled") == Some(&Value::Bool(true))
            && state.get("requesting_principal_enabled") == Some(&Value::Bool(true))
    });
    let outcome_invariants = match decision {
        Some("allow") => {
            principal_enabled
                && binding_revocation == Some(&Value::Null)
                && delegation_resolution == Some("resolved")
                && delegation_record.is_some_and(|value| !value.is_null())
                && delegation_revocation == Some(&Value::Null)
        }
        Some("deny") => {
            if string(value, "reason_code") == Some("proof.authorization.delegation_unavailable") {
                delegation_resolution == Some("not_found_or_hidden")
                    && delegation_record == Some(&Value::Null)
                    && delegation_revocation == Some(&Value::Null)
            } else {
                true
            }
        }
        _ => false,
    };
    let operation_name = operation.and_then(|operation| string(operation, "name"));
    let operation_version = operation.and_then(|operation| string(operation, "version"));
    let localized_commitment = value.get("localized_consequence_commitment");
    let localized_invariants = match (
        decision,
        operation_output_contract(operation_name, operation_version),
    ) {
        (Some("allow"), Some(expected_contract)) => {
            localized_commitment.is_some_and(|commitment| {
                object_keys_exact(
                    commitment,
                    &[
                        "application_consequence_digest",
                        "result_contract",
                        "result_digest",
                        "result_kind",
                    ],
                ) && matches!(
                    string(commitment, "result_kind"),
                    Some("success" | "failure")
                ) && string(commitment, "result_contract").is_some_and(|contract| {
                    contract == expected_contract
                        || contract == "proof.dev/result/localized-operation-problem/v1"
                }) && digest_field(commitment, "result_digest").is_some()
                    && digest_field(commitment, "application_consequence_digest").is_some()
            })
        }
        (Some("allow"), None) | (Some("deny"), _) => localized_commitment.is_none(),
        _ => false,
    };
    keys_match
        && common_authority_fields_valid(value)
        && operation_valid
        && string(value, "evaluated_at")
            .and_then(parse_timestamp)
            .is_some()
        && string(value, "audience")
            == string(value, "workspace_id")
                .map(|workspace| format!("proof://workspace/{workspace}"))
                .as_deref()
        && value.get("presentation_consumed") == Some(&Value::Bool(true))
        && digest_field(value, "command_digest").is_some()
        && digest_field(value, "command_envelope_digest").is_some()
        && digest_field(value, "actor_context_digest").is_some()
        && digest_field(value, "requesting_subject_commitment").is_some()
        && digest_field(value, "policy_bundle_digest").is_some()
        && head.is_some_and(|head| {
            object_keys_exact(head, &["record_digest", "sequence"])
                && u64_field(head, "sequence").is_some()
                && digest_field(head, "record_digest").is_some()
        })
        && binding_sequence
            .zip(head_sequence)
            .is_some_and(|(binding, head)| binding <= head)
        && binding.is_some_and(|binding| {
            object_keys_exact(
                binding,
                &[
                    "authority_sequence",
                    "binding_id",
                    "record_digest",
                    "revocation_record_digest",
                ],
            ) && u64_field(binding, "authority_sequence").is_some()
                && digest_field(binding, "record_digest").is_some()
                && optional_digest_field(binding, "revocation_record_digest").is_some()
        })
        && delegation.is_some_and(|delegation| {
            object_keys_exact(
                delegation,
                &[
                    "delegation_id",
                    "record_digest",
                    "resolution",
                    "revocation_record_digest",
                ],
            ) && optional_digest_field(delegation, "record_digest").is_some()
                && optional_digest_field(delegation, "revocation_record_digest").is_some()
                && matches!(
                    string(delegation, "resolution"),
                    Some("resolved" | "not_found_or_hidden")
                )
        })
        && principal_state.is_some_and(|state| {
            object_keys_exact(
                state,
                &[
                    "operating_principal_enabled",
                    "requesting_principal_enabled",
                ],
            ) && state
                .get("operating_principal_enabled")
                .is_some_and(Value::is_boolean)
                && state
                    .get("requesting_principal_enabled")
                    .is_some_and(Value::is_boolean)
        })
        && requested.is_some_and(|requested| {
            object_keys_exact(
                requested,
                &[
                    "changeset_ids",
                    "edition_ids",
                    "environment_ids",
                    "locales",
                    "object_ids",
                    "release_ids",
                    "schema_ids",
                    "workspace_ids",
                ],
            ) && requested.get("workspace_ids")
                == Some(&Value::Array(vec![Value::String(
                    string(value, "workspace_id").unwrap_or_default().to_owned(),
                )]))
                && [
                    "changeset_ids",
                    "edition_ids",
                    "environment_ids",
                    "locales",
                    "object_ids",
                    "release_ids",
                    "schema_ids",
                ]
                .into_iter()
                .all(|field| sorted_unique_strings(requested.get(field), 0, 100))
        })
        && constraints.is_some_and(|constraints| {
            object_keys_exact(
                constraints,
                &[
                    "max_context_bytes",
                    "max_edits_per_changeset",
                    "max_objects",
                ],
            ) && u64_field(constraints, "max_objects")
                .is_some_and(|value| (1..=100).contains(&value))
                && u64_field(constraints, "max_edits_per_changeset")
                    .is_some_and(|value| (1..=100).contains(&value))
                && u64_field(constraints, "max_context_bytes")
                    .is_some_and(|value| (1..=1_048_576).contains(&value))
        })
        && decision_valid
        && outcome_invariants
        && localized_invariants
}

fn authorization_denial_reason_is_valid(reason: &str) -> bool {
    matches!(
        reason,
        "proof.auth.binding_inactive"
            | "proof.authorization.budget_exceeded"
            | "proof.authorization.delegation_expired"
            | "proof.authorization.delegation_not_yet_valid"
            | "proof.authorization.delegation_revoked"
            | "proof.authorization.delegation_unavailable"
            | "proof.authorization.policy_denied"
            | "proof.authorization.principal_disabled"
            | "proof.authorization.scope_exceeded"
            | "proof.delegation.chain_unsupported"
            | "proof.idempotency.key_reused"
    )
}

fn operation_output_contract(name: Option<&str>, version: Option<&str>) -> Option<&'static str> {
    match (name, version) {
        (Some("changeset.add"), Some("proof.dev/operation/changeset.add/v2")) => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "changeSetAddOutput"
        )),
        (Some("changeset.commit"), Some("proof.dev/operation/changeset.commit/v2")) => {
            Some(concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "changeSetCommitOutput"
            ))
        }
        (Some("changeset.create"), Some("proof.dev/operation/changeset.create/v2")) => {
            Some(concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "changeSetCreateOutput"
            ))
        }
        (Some("changeset.diff"), Some("proof.dev/operation/changeset.diff/v2")) => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "changeSetDiffOutput"
        )),
        (Some("changeset.get"), Some("proof.dev/operation/changeset.get/v2")) => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "changeSetGetOutput"
        )),
        (Some("changeset.submit"), Some("proof.dev/operation/changeset.submit/v2")) => {
            Some(concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "changeSetSubmitOutput"
            ))
        }
        (Some("changeset.validate"), Some("proof.dev/operation/changeset.validate/v2")) => {
            Some(concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "changeSetValidateOutput"
            ))
        }
        (Some("context.build"), Some("proof.dev/operation/context.build/v2")) => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "contextBuildOutput"
        )),
        (Some("edition.create"), Some("proof.dev/operation/edition.create/v2")) => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "editionCreateOutput"
        )),
        (Some("object.query_released"), Some("proof.dev/operation/object.query_released/v2")) => {
            Some(concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "objectQueryReleasedOutput"
            ))
        }
        (Some("release.create"), Some("proof.dev/operation/release.create/v2")) => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "releaseCreateOutput"
        )),
        _ => None,
    }
}

fn operation_action(name: Option<&str>, version: Option<&str>) -> Option<&'static str> {
    match (name, version) {
        (Some("changeset.add"), Some("proof.dev/operation/changeset.add/v2")) => {
            Some("changeset:add")
        }
        (Some("changeset.commit"), Some("proof.dev/operation/changeset.commit/v2")) => {
            Some("changeset:commit")
        }
        (Some("changeset.create"), Some("proof.dev/operation/changeset.create/v2")) => {
            Some("changeset:create")
        }
        (Some("changeset.diff"), Some("proof.dev/operation/changeset.diff/v2")) => {
            Some("changeset:diff")
        }
        (Some("changeset.get"), Some("proof.dev/operation/changeset.get/v2")) => {
            Some("changeset:get")
        }
        (Some("changeset.submit"), Some("proof.dev/operation/changeset.submit/v2")) => {
            Some("changeset:submit")
        }
        (Some("changeset.validate"), Some("proof.dev/operation/changeset.validate/v2")) => {
            Some("changeset:validate")
        }
        (
            Some("context.build"),
            Some("proof.dev/operation/context.build/v1" | "proof.dev/operation/context.build/v2"),
        ) => Some("context:build"),
        (Some("edition.create"), Some("proof.dev/operation/edition.create/v2")) => {
            Some("edition:create")
        }
        (
            Some("object.query_released"),
            Some(
                "proof.dev/operation/object.query_released/v1"
                | "proof.dev/operation/object.query_released/v2",
            ),
        ) => Some("object:query_released"),
        (Some("release.create"), Some("proof.dev/operation/release.create/v2")) => {
            Some("release:create")
        }
        (Some("workspace.status"), Some("proof.dev/operation/workspace.status/v1")) => {
            Some("workspace:status")
        }
        _ => None,
    }
}

fn root_transition_shape_is_valid(value: &Value) -> bool {
    let successor = string(value, "successor_authority_key_id")
        .zip(string(value, "successor_public_key"))
        .and_then(|(key_id, public_key)| parse_public_signer(key_id, public_key).ok());
    object_keys_exact(
        value,
        &[
            "activated_at",
            "activated_by_principal_id",
            "algorithm",
            "api_version",
            "authority_sequence",
            "predecessor_authority_key_id",
            "previous_authority_record_digest",
            "successor_authority_key_id",
            "successor_public_key",
            "transition_id",
            "workspace_id",
        ],
    ) && common_authority_fields_valid(value)
        && string(value, "algorithm") == Some("ed25519")
        && successor.is_some()
        && string(value, "predecessor_authority_key_id")
            != string(value, "successor_authority_key_id")
        && string(value, "activated_at")
            .and_then(parse_timestamp)
            .is_some()
}

fn string<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn u64_field(value: &Value, field: &str) -> Option<u64> {
    value.get(field).and_then(Value::as_u64)
}

fn digest_field(value: &Value, field: &str) -> Option<Digest> {
    string(value, field).and_then(Digest::parse)
}

fn digest_path(value: &Value, path: &[&str]) -> Option<Digest> {
    let mut current = value;
    for component in path {
        current = current.get(*component)?;
    }
    current.as_str().and_then(Digest::parse)
}

fn optional_digest_field(value: &Value, field: &str) -> Option<Option<Digest>> {
    match value.get(field) {
        Some(Value::Null) => Some(None),
        Some(Value::String(value)) => Digest::parse(value).map(Some),
        _ => None,
    }
}

fn contains_raw_uid(value: &Value) -> bool {
    match value {
        Value::String(value) => value.starts_with("uid:"),
        Value::Array(values) => values.iter().any(contains_raw_uid),
        Value::Object(values) => values.values().any(contains_raw_uid),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn valid_unix_subject(value: &str) -> bool {
    let Some(uid) = value.strip_prefix("uid:") else {
        return false;
    };
    !uid.is_empty()
        && uid.len() <= 20
        && uid.bytes().all(|byte| byte.is_ascii_digit())
        && (uid == "0" || !uid.starts_with('0'))
}

fn object_keys_exact(value: &Value, expected: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn array_subset(requested: Option<&Value>, permitted: Option<&Value>) -> bool {
    requested
        .and_then(Value::as_array)
        .zip(permitted.and_then(Value::as_array))
        .is_some_and(|(requested, permitted)| {
            requested.iter().all(|value| permitted.contains(value))
        })
}

fn invalid(
    report: &mut Report,
    dimension: &str,
    code: &str,
    digest: Option<Digest>,
    sequence: Option<u64>,
) {
    report.finding(dimension, DimensionStatus::Invalid, code, digest, sequence);
}

fn incomplete(
    report: &mut Report,
    dimension: &str,
    code: &str,
    digest: Option<Digest>,
    sequence: Option<u64>,
) {
    report.finding(
        dimension,
        DimensionStatus::Incomplete,
        code,
        digest,
        sequence,
    );
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{
        container::{LoadedArtifact, LoadedBundle},
        model::{
            ArtifactDescriptor, ArtifactRef, AuthorityHead, Availability, Bundle, Entrypoints,
        },
    };

    const WORKSPACE: &str = "019c0000-0000-7000-8000-000000000001";

    fn reference(kind: ArtifactKind, tag: u8) -> ArtifactRef {
        ArtifactRef {
            artifact_kind: kind,
            digest: Digest([tag; 32]),
        }
    }

    fn reference_value(
        reference: ArtifactRef,
        api_version: &str,
        id: Option<(&str, &str)>,
    ) -> Value {
        let mut value = json!({
            "api_version": api_version,
            "digest": reference.digest,
        });
        if let Some((field, value_id)) = id {
            value[field] = Value::String(value_id.to_owned());
        }
        value
    }

    fn empty_loaded() -> LoadedBundle {
        let placeholder = reference(ArtifactKind::ReleaseV2, 0xf0);
        LoadedBundle {
            bundle: Bundle {
                api_version: crate::model::BUNDLE_API_VERSION.to_owned(),
                workspace_id: WORKSPACE.to_owned(),
                entrypoints: Entrypoints {
                    target_release_manifest: placeholder,
                    target_release_proof_envelope: reference(ArtifactKind::ProofEnvelopeV1, 0xf1),
                    target_authorization_record_digest: Digest([0xf2; 32]),
                    target_localized_consequence: reference(
                        ArtifactKind::AuthenticatedLocalizedConsequenceV1,
                        0xf3,
                    ),
                },
                included_authority_head: AuthorityHead {
                    sequence: 1,
                    record_digest: Digest([0xf4; 32]),
                },
                authority_prefix: Vec::new(),
                artifacts: Vec::new(),
            },
            manifest_digest: Digest([0xf5; 32]),
            artifacts: BTreeMap::new(),
            missing_external: BTreeSet::new(),
        }
    }

    fn insert(loaded: &mut LoadedBundle, role: EvidenceRole, reference: ArtifactRef, value: Value) {
        let bytes = canonical_bytes(&value).unwrap();
        loaded.bundle.artifacts.push(ArtifactDescriptor {
            role,
            artifact: reference,
            availability: Availability::Included {
                byte_length: u64::try_from(bytes.len()).unwrap(),
            },
        });
        loaded
            .artifacts
            .insert(reference, LoadedArtifact { bytes, value });
    }

    fn rollback_case(broken_ancestry: bool) -> (LoadedBundle, Value, Value, Value) {
        let mut loaded = empty_loaded();
        let target_state_ref = reference(ArtifactKind::KnownStateV1, 0x11);
        let base_state_ref = reference(ArtifactKind::KnownStateV2, 0x12);
        let target_edition_ref = reference(ArtifactKind::EditionV1, 0x13);
        let base_edition_ref = reference(ArtifactKind::EditionV2, 0x14);
        let historical_release_ref = reference(ArtifactKind::ReleaseV2, 0x15);
        let current_release_ref = reference(ArtifactKind::ReleaseV2, 0x16);
        let target_state_reference = json!({
            "api_version": "proof.dev/known-state/v1",
            "authoritative_sequence": 1,
            "digest": target_state_ref.digest,
        });
        let base_state_reference = json!({
            "api_version": "proof.dev/known-state/v2",
            "authoritative_sequence": 2,
            "digest": base_state_ref.digest,
        });
        let target_edition_reference = reference_value(
            target_edition_ref,
            "proof.dev/edition/v1",
            Some(("edition_id", "019c0000-0000-7000-8000-000000000011")),
        );
        let base_edition_reference = reference_value(
            base_edition_ref,
            "proof.dev/edition/v2",
            Some(("edition_id", "019c0000-0000-7000-8000-000000000012")),
        );
        insert(
            &mut loaded,
            EvidenceRole::KnownState,
            target_state_ref,
            json!({
                "api_version": "proof.dev/known-state/v1",
                "authoritative_sequence": 1,
                "workspace_id": WORKSPACE,
            }),
        );
        insert(
            &mut loaded,
            EvidenceRole::KnownState,
            base_state_ref,
            json!({
                "api_version": "proof.dev/known-state/v2",
                "authoritative_sequence": 2,
                "objects": [],
                "previous_state": target_state_reference,
                "renditions": [],
                "schemas": [],
                "workspace_id": WORKSPACE,
            }),
        );
        insert(
            &mut loaded,
            EvidenceRole::Edition,
            target_edition_ref,
            json!({
                "api_version": "proof.dev/edition/v1",
                "authoritative_sequence": 1,
                "state_digest": target_state_ref.digest,
                "workspace_id": WORKSPACE,
            }),
        );
        insert(
            &mut loaded,
            EvidenceRole::Edition,
            base_edition_ref,
            json!({
                "api_version": "proof.dev/edition/v2",
                "edition_id": "019c0000-0000-7000-8000-000000000012",
                "state": base_state_reference,
                "workspace_id": WORKSPACE,
            }),
        );
        let release_a = json!({
            "api_version": "proof.dev/release/v2",
            "base_release": null,
            "edition": target_edition_reference,
            "environment_id": "preview",
            "release_id": "019c0000-0000-7000-8000-000000000021",
            "release_sequence": 1,
            "released_at": "2026-08-21T10:00:00Z",
            "workspace_id": WORKSPACE,
        });
        let historical_release_reference = json!({
            "api_version": "proof.dev/release/v2",
            "digest": historical_release_ref.digest,
            "release_id": "019c0000-0000-7000-8000-000000000021",
        });
        let release_b_base = if broken_ancestry {
            json!({
                "api_version": "proof.dev/release/v2",
                "digest": Digest([0xee; 32]),
                "release_id": "019c0000-0000-7000-8000-000000000021",
            })
        } else {
            historical_release_reference
        };
        let release_b = json!({
            "api_version": "proof.dev/release/v2",
            "base_release": release_b_base,
            "edition": base_edition_reference,
            "environment_id": "preview",
            "release_id": "019c0000-0000-7000-8000-000000000022",
            "release_sequence": 2,
            "released_at": "2026-08-21T11:00:00Z",
            "workspace_id": WORKSPACE,
        });
        insert(
            &mut loaded,
            EvidenceRole::ReleaseManifest,
            historical_release_ref,
            release_a,
        );
        insert(
            &mut loaded,
            EvidenceRole::ReleaseManifest,
            current_release_ref,
            release_b,
        );
        let current_release_reference = json!({
            "api_version": "proof.dev/release/v2",
            "digest": current_release_ref.digest,
            "release_id": "019c0000-0000-7000-8000-000000000022",
        });
        let delta = json!({
            "api_version": "proof.dev/edition-delta/v2",
            "base": {
                "edition": base_edition_reference,
                "state": base_state_reference,
            },
            "objects": [],
            "renditions": [],
            "schemas": [],
            "target": {
                "edition": target_edition_reference,
                "state": target_state_reference,
            },
        });
        let manifest = json!({
            "base_release": current_release_reference,
            "changeset_id": null,
            "edition": target_edition_reference,
            "environment_id": "preview",
            "kind": "rollback",
            "release_id": "019c0000-0000-7000-8000-000000000023",
            "release_sequence": 3,
            "released_at": "2026-08-21T12:00:00Z",
            "resource_intent_id": null,
            "rollback_target_release_id": "019c0000-0000-7000-8000-000000000021",
        });
        let predicate = json!({
            "content_evidence": null,
            "release": { "edition": target_edition_reference },
            "state": target_state_reference,
        });
        (loaded, predicate, manifest, delta)
    }

    #[test]
    fn rollback_accepts_a_transitive_historical_edition_and_rejects_broken_ancestry() {
        let (loaded, predicate, manifest, delta) = rollback_case(false);
        assert_eq!(
            verify_rollback_content(&loaded, &predicate, &manifest, &delta),
            Ok(())
        );

        let (loaded, predicate, manifest, delta) = rollback_case(true);
        assert_eq!(
            verify_rollback_content(&loaded, &predicate, &manifest, &delta),
            Err("proof.verify.content.rollback_ancestry")
        );
    }

    #[test]
    fn authority_record_union_and_operation_contracts_are_closed() {
        let valid = json!({
            "api_version": "proof.dev/principal-status/v1",
            "authority_sequence": 1,
            "enabled": true,
            "previous_authority_record_digest": null,
            "principal_id": "019c0000-0000-7000-8000-000000000002",
            "principal_type": "human",
            "recorded_at": "2026-08-21T10:00:00Z",
            "recorded_by_principal_id": "019c0000-0000-7000-8000-000000000002",
            "workspace_id": WORKSPACE,
        });
        assert!(authority_record_shape_is_valid(&valid));
        let mut unknown = valid.clone();
        unknown["api_version"] = Value::String("proof.dev/attacker-record/v1".to_owned());
        assert!(!authority_record_shape_is_valid(&unknown));
        let mut extra = valid;
        extra["attacker_extension"] = Value::Bool(true);
        assert!(!authority_record_shape_is_valid(&extra));
        assert!(!authorization_denial_reason_is_valid(
            "proof.attacker.allow"
        ));
        assert_eq!(
            operation_output_contract(
                Some("release.create"),
                Some("proof.dev/operation/release.create/v2")
            ),
            Some(concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "releaseCreateOutput"
            ))
        );
        assert_eq!(
            operation_output_contract(
                Some("release.create"),
                Some("proof.dev/operation/release.create/v999")
            ),
            None
        );
    }

    #[test]
    fn authority_root_rotation_rejects_reuse_and_release_key_collision() {
        fn signer(seed: u8) -> PublicSigner {
            let public_key = SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes();
            let key_id = format!("ed25519:{}", hex_key(public_key));
            parse_public_signer(&key_id, &BASE64.encode(public_key)).unwrap()
        }

        let initial = signer(0x11);
        let successor = signer(0x22);
        let release = signer(0x33);
        let mut seen_ids = BTreeSet::from([initial.key_id.clone()]);
        let mut seen_keys = BTreeSet::from([initial.public_key]);
        assert!(successor_key_is_fresh(
            &successor,
            &mut seen_ids,
            &mut seen_keys,
            std::slice::from_ref(&release)
        ));
        assert!(!successor_key_is_fresh(
            &initial,
            &mut seen_ids,
            &mut seen_keys,
            std::slice::from_ref(&release)
        ));
        assert!(!successor_key_is_fresh(
            &release,
            &mut seen_ids,
            &mut seen_keys,
            std::slice::from_ref(&release)
        ));
    }

    #[test]
    fn revocation_resolution_is_restricted_to_the_decision_causal_head_and_time() {
        let revocation_digest = Digest([0x55; 32]);
        let revocation = VerifiedAuthorityRecord {
            sequence: 6,
            digest: revocation_digest,
            value: json!({
                "api_version": "proof.dev/principal-binding-revocation/v1",
                "binding_id": "019c0000-0000-7000-8000-000000000004",
            }),
            recorded_at: parse_timestamp("2026-08-21T10:12:00Z").unwrap(),
        };
        let records = BTreeMap::from([(revocation_digest, &revocation)]);
        let reference = Value::String(revocation_digest.to_string());
        let expected = Some("019c0000-0000-7000-8000-000000000004");

        assert_eq!(
            decision_revocation_record(
                Some(&reference),
                &records,
                "proof.dev/principal-binding-revocation/v1",
                "binding_id",
                expected,
                Some(5),
                parse_timestamp("2026-08-21T10:13:00Z"),
            ),
            None
        );
        assert_eq!(
            decision_revocation_record(
                Some(&reference),
                &records,
                "proof.dev/principal-binding-revocation/v1",
                "binding_id",
                expected,
                Some(6),
                parse_timestamp("2026-08-21T10:11:00Z"),
            ),
            None
        );
        assert_eq!(
            decision_revocation_record(
                Some(&reference),
                &records,
                "proof.dev/principal-binding-revocation/v1",
                "binding_id",
                expected,
                Some(6),
                parse_timestamp("2026-08-21T10:13:00Z"),
            ),
            Some(true)
        );
    }

    #[test]
    fn portable_release_key_metadata_is_workspace_scoped_and_conflict_free() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let key_hex = hex_key(public_key);
        let key_id = format!("ed25519:{key_hex}");
        let metadata = json!({
            "algorithm": "ed25519",
            "api_version": "proof.dev/signing-key-metadata/v1",
            "key_id": key_id,
            "not_before": "2026-08-21T10:00:00Z",
            "public_key": key_hex,
            "trust_profile": "proof.local/release-proof/v1",
        });
        let metadata_digest = domain_digest(
            ArtifactKind::PolicyBundleV1,
            &canonical_bytes(&metadata).unwrap(),
        );
        let wrapper = json!({
            "algorithm": "ed25519",
            "api_version": "proof.dev/release-signing-key/v1",
            "key_id": key_id,
            "metadata": metadata,
            "native_metadata_digest": metadata_digest,
            "not_before": "2026-08-21T10:00:00Z",
            "public_key": key_hex,
            "trust_profile": "proof.local/release-proof/v1",
            "workspace_id": WORKSPACE,
        });
        let bytes = canonical_bytes(&wrapper).unwrap();
        let artifact = LoadedArtifact {
            bytes,
            value: wrapper.clone(),
        };
        assert!(release_key_wrapper(&artifact, WORKSPACE).is_some());
        assert!(release_key_wrapper(&artifact, "different-workspace").is_none());

        let mut loaded = empty_loaded();
        insert(
            &mut loaded,
            EvidenceRole::ReleaseSigningKey,
            reference(ArtifactKind::ReleaseSigningKeyV1, 0x31),
            wrapper.clone(),
        );
        let trusted = TrustedKey {
            key_id: key_id.clone(),
            public_key: BASE64.encode(public_key),
            not_before: "2026-08-21T00:00:00Z".to_owned(),
            not_after: None,
            revoked_at: None,
        };
        assert!(verify_release_key_evidence(
            &loaded,
            &trusted,
            Some(&key_id),
            parse_timestamp("2026-08-21T12:00:00Z")
        ));
        let native_revocation = json!({
            "api_version": "proof.dev/signing-key-revocation/v1",
            "key_id": key_id,
            "reason": "rotation",
            "revoked_at": "2026-08-21T13:00:00Z",
        });
        let revocation = json!({
            "api_version": "proof.dev/release-signing-key-revocation/v1",
            "key_id": key_id,
            "native_revocation": native_revocation,
            "native_revocation_digest": domain_digest(
                ArtifactKind::PolicyBundleV1,
                &canonical_bytes(&native_revocation).unwrap()
            ),
            "reason": "rotation",
            "revoked_at": "2026-08-21T13:00:00Z",
            "workspace_id": WORKSPACE,
        });
        let revocation_artifact = LoadedArtifact {
            bytes: canonical_bytes(&revocation).unwrap(),
            value: revocation.clone(),
        };
        assert!(release_key_revocation_wrapper(&revocation_artifact, WORKSPACE).is_some());
        assert!(
            release_key_revocation_wrapper(&revocation_artifact, "different-workspace").is_none()
        );
        insert(
            &mut loaded,
            EvidenceRole::ReleaseSigningKeyRevocation,
            reference(ArtifactKind::ReleaseSigningKeyRevocationV1, 0x33),
            revocation,
        );
        assert!(verify_release_key_evidence(
            &loaded,
            &trusted,
            Some(&key_id),
            parse_timestamp("2026-08-21T12:00:00Z")
        ));
        assert!(!verify_release_key_evidence(
            &loaded,
            &trusted,
            Some(&key_id),
            parse_timestamp("2026-08-21T14:00:00Z")
        ));
        let mut conflicting = wrapper;
        conflicting["not_before"] = Value::String("2026-08-21T11:00:00Z".to_owned());
        conflicting["metadata"]["not_before"] = Value::String("2026-08-21T11:00:00Z".to_owned());
        let conflict_metadata = conflicting["metadata"].clone();
        conflicting["native_metadata_digest"] = serde_json::to_value(domain_digest(
            ArtifactKind::PolicyBundleV1,
            &canonical_bytes(&conflict_metadata).unwrap(),
        ))
        .unwrap();
        insert(
            &mut loaded,
            EvidenceRole::ReleaseSigningKey,
            reference(ArtifactKind::ReleaseSigningKeyV1, 0x32),
            conflicting,
        );
        assert!(!verify_release_key_evidence(
            &loaded,
            &trusted,
            Some(&key_id),
            parse_timestamp("2026-08-21T12:00:00Z")
        ));
    }
}
