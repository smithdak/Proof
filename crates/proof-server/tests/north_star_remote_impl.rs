//! The complete remote north-star qualification scenario (P-0013 Milestone 3
//! acceptance criterion): two Humans (`H1` requester/initiator and `H2`
//! approver/publisher) plus one Agent (`G` operator) exercised end to end
//! through the in-process axum HTTP server and an isolated PostgreSQL schema.
//!
//! Step order follows the accepted contract §"Exact remote north star":
//! capabilities discovery, deterministic-issuer OIDC sessions for both Humans,
//! role assignment, Delegation, delegated ContextPack build, two Object
//! creations and four locale puts with one policy repair, Human approval with
//! separation-of-duties rejections, idempotent atomic commit, pre/post-Release
//! register reads, Edition and Release creation, outbox delivery to private
//! preview with a ready-gated alias, keyed `evidence.export/v2` capture with
//! byte-identical replay, worker assembly to ready, reserved-digest lifecycle
//! reads, exact kind-and-digest artifact acquisition without cross-kind
//! aliases, and the offline `proof-verifier` leg over the fetched logical
//! member map under explicit caller trust.

#![allow(
    clippy::doc_markdown,
    clippy::duration_suboptimal_units,
    clippy::similar_names,
    clippy::struct_field_names,
    clippy::too_many_lines
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signer as _, SigningKey};
use proof_application::authority::{
    AgentPrincipalType, AuthenticatedCommandApiVersion, AuthenticatedCommandEnvelopeJson,
    AuthenticatedCommandKeyUsage, AuthenticatedCommandV1, AuthenticatedInvocationApiVersion,
    AuthenticatedInvocationV1, AuthorityAudience, AuthorityOperation, AuthoritySequence,
    CommandInputApiVersion, CommandInputV1, Ed25519Algorithm, Ed25519KeyId, Ed25519PublicKey,
    LocalEd25519AuthenticatedSubjectV1, PrincipalBindingApiVersion, PrincipalBindingV1,
};
use proof_attestation::authority::{AuthorityPayloadProfile, sign_authority_payload};
use proof_attestation::{Ed25519SigningProvider, ProofSigningProvider};
use proof_canonical::{canonicalize, digest, object_revision_digest};
use proof_delivery::preview::{PreviewAdapter, PreviewBlobV1, PreviewSnapshotV1};
use proof_delivery::worker::{AcknowledgeOutcome, OutboxWorker, WorkerConfig};
use proof_domain::{ArtifactKind, ContentDigest, Timestamp};
use proof_pg::{PgConfig, schema::ALL_TABLE_DDL, wiring::PgRuntime};
use proof_remote::authority::WorkspaceRole as Role;
use proof_remote::identity::{
    AuthenticatedActorContextV2, OidcAuthenticatedSubjectApiVersion, OidcAuthenticatedSubjectV1,
    OidcPrincipalBindingApiVersion, OidcPrincipalBindingPrivateApiVersion,
    OidcPrincipalBindingPrivateV1, OidcPrincipalBindingV1, OidcSubjectCommitmentInputApiVersion,
    OidcSubjectCommitmentInputV1, OidcSubjectCommitmentOpeningApiVersion,
    OidcSubjectCommitmentOpeningV1, encode_blind, subject_commitment_digest,
};
use proof_remote::oracle::IdentityFixtureV1;
use proof_remote::{
    AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT, AcceptedArtifactAvailabilityV1,
    AcceptedArtifactDescriptorV1, AcceptedArtifactRefV1, AcceptedArtifactRoleBindingV1,
    ApplicationConsequenceOutcome, ApplicationKeyKind, AuthorityHeadV1,
    COMPLETE_HTTP_OPERATION_REGISTRY_SHA256, EvidenceExportResultV2, EvidenceExportStatusKind,
    EvidenceExportStatusV1, REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT,
    REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT, REMOTE_AUTHORIZATION_PROJECTION_SHA256,
    REMOTE_EVIDENCE_BUNDLE_DIGEST_CONTEXT, REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT,
    REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT, RemoteApplicationConsequenceV1,
    RemoteAuthorityRecordSetApiVersion, RemoteAuthorityRecordSetV1, RemoteAuthorityRecordV1,
    RemoteOperationV1, RemoteReleaseArtifactClosureApiVersion,
    RemoteReleaseArtifactClosureEntrypointsV1, RemoteReleaseArtifactClosureV1,
    VERIFICATION_TRUST_POLICY_DIGEST_CONTEXT, VerificationReasonCode, VerificationStatus,
    derive_key_digest,
};
use proof_server::export::{
    ExportWorker, build_bundle_descriptor, build_manifest, evidence_export_get_v1,
    evidence_export_v2,
};
use proof_server::routes::router;
use proof_server::session::SessionRecord;
use proof_server::{AppState, ServerConfig};
use proof_verifier::{
    RemoteAuthoritySuffixInput, verify_remote_authority_suffix, verify_remote_evidence_v2,
};
use serde_json::{Map, Value, json};
use tower::ServiceExt;

const WS_ID: &str = "019c0000-0000-7000-8000-000000000001";
const H1_REQUESTER: &str = "019c0000-0000-7000-8000-000000000002";
const H2_APPROVER: &str = "019c0000-0000-7000-8000-000000000003";
const G_OPERATOR: &str = "019c0000-0000-7000-8000-000000000004";
const H1_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000005";
const H2_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000006";
const AGENT_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000007";
const H1_SUBJECT: &str = "north-star-h1-requester";
const H2_SUBJECT: &str = "north-star-h2-approver";
const DELEGATION_ID: &str = "019c0000-0000-7000-8000-000000000008";
const CHANGES_ET_ID: &str = "019d0000-0000-7000-8000-000000000010";
const EDITION_ID: &str = "019d0000-0000-7000-8000-000000000011";
const RELEASE_ID: &str = "019d0000-0000-7000-8000-000000000020";
const RELEASE_APPLICATION_KEY: &str = "019d0000-0000-7000-8000-0000000000d9";
const HTTP_CORRELATION_ID: &str = "019d0000-0000-7000-8000-0000000000c0";
const EXPORT_APPLICATION_KEY: &str = "019d0000-0000-7000-8000-000000000041";
const INITIAL_ADD_APPLICATION_KEY: &str = "019d0000-0000-7000-8000-000000000066";
const REPAIR_ADD_APPLICATION_KEY: &str = "019d0000-0000-7000-8000-000000000067";
const RESOURCE_INTENT_ID: &str = "019f0000-0000-7000-8000-000000000010";
const CONTEXT_PACK_ID: &str = "019f0000-0000-7000-8000-000000000011";
const CREATED_OBJECT_A_ID: &str = "019f0000-0000-7000-8000-000000000020";
const CREATED_OBJECT_B_ID: &str = "019f0000-0000-7000-8000-000000000021";
const CREATE_A_EDIT_ID: &str = "6220cdbd-c1dd-706a-bbcc-eed30ab892b9";
const PUT_A_EDIT_ID: &str = "1ba11466-639a-781a-bb1b-234c4577402b";
const CREATE_B_EDIT_ID: &str = "4a91fb50-c282-72d9-8018-e47da1a9e187";
const PUT_B_EDIT_ID: &str = "06913491-b153-7882-b089-03d2a8720acd";
const BASE_EDITION_ID: &str = "019f0000-0000-7000-8000-000000000040";
const BASE_RELEASE_ID: &str = "019f0000-0000-7000-8000-000000000041";
const BASE_PROOF_ID: &str = "019f0000-0000-7000-8000-000000000042";
const PROOF_ID: &str = "019f0000-0000-7000-8000-000000000043";
const OBJECT_A_SCHEMA_ID: &str = "article";
const OBJECT_B_SCHEMA_ID: &str = "product";
const EN_LOCALE: &str = "en";
const FR_CA_LOCALE: &str = "fr-CA";
const FORBIDDEN_LEGAL_CLAIM: &str = "Forbidden terms";
const BASE_CONTENT_SEQUENCE: u64 = 2;
const TARGET_CONTENT_SEQUENCE: u64 = BASE_CONTENT_SEQUENCE + 6;
const CONTENT_ISSUED_AT: &str = "2026-08-26T12:00:00Z";
const CONTEXT_CREATED_AT: &str = "2026-08-26T12:01:00Z";
const CHANGESET_CREATED_AT: &str = "2026-08-26T12:02:00Z";
const CHANGESET_SUBMITTED_AT: &str = "2026-08-26T12:03:00Z";
const CHANGESET_APPROVED_AT: &str = "2026-08-26T12:04:00Z";
const CHANGESET_COMMITTED_AT: &str = "2026-08-26T12:05:00Z";
const EDITION_CREATED_AT: &str = "2026-08-26T12:06:00Z";
const RELEASED_AT: &str = "2026-08-26T12:07:00Z";
const CONTEXT_EXPIRES_AT: &str = "2027-08-26T12:01:00Z";

const ZERO_DIGEST_STR: &str =
    "blake3:0000000000000000000000000000000000000000000000000000000000000000";

static SCHEMA_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn dsn() -> String {
    std::env::var("PROOF_PG_DSN").unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
}

fn fixed_digest(byte: u8) -> ContentDigest {
    ContentDigest::blake3([byte; 32])
}

fn artifact_digest(kind: ArtifactKind, bytes: &[u8]) -> ContentDigest {
    domain_digest(kind.derive_key_context(), bytes)
}

fn now_timestamp() -> Timestamp {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    Timestamp::from_unix_timestamp_nanos(i128::try_from(duration.as_nanos()).unwrap()).unwrap()
}

fn timestamp_offset(seconds: i64) -> Timestamp {
    let nanos = now_timestamp().unix_timestamp_nanos() + i128::from(seconds) * 1_000_000_000;
    Timestamp::from_unix_timestamp_nanos(nanos).unwrap()
}

fn byte_len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap()
}

fn canonical_bytes(value: &Value) -> Vec<u8> {
    canonicalize(value).unwrap().as_bytes().to_vec()
}

fn domain_digest(context: &str, bytes: &[u8]) -> ContentDigest {
    derive_key_digest(context, bytes)
}

// ---------------------------------------------------------------------------
// Isolated PostgreSQL schema harness.
// ---------------------------------------------------------------------------

struct TestDb {
    state: AppState,
    cleanup: std::sync::Mutex<PgRuntime>,
    schema: String,
}

#[derive(Debug, Eq, PartialEq)]
struct ProducerInputFact {
    fact_id: String,
    fact_kind: String,
    authority_sequence: i64,
    fact_digest: String,
    body: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
struct ProducerInputSnapshot {
    facts: Vec<ProducerInputFact>,
    transaction_sequence: i64,
    authority_sequence: i64,
    content_sequence: i64,
    release_sequence: i64,
    authority_head_digest: Option<String>,
    content_head_digest: Option<String>,
    release_head_digest: Option<String>,
}

struct ReleaseDeliveryRow {
    event_id: String,
    delivery_id: String,
    workspace_transaction_sequence: i64,
    ordinal: i64,
    ordering_key: String,
    stream_sequence: i64,
    effect_digest: String,
    payload_digest: Option<String>,
    artifact_kind: Option<String>,
    artifact_digest: Option<String>,
    destination_configuration_version: i64,
    destination_configuration_digest: String,
    correlation_id: Option<String>,
    status: String,
    next_attempt_scheduled: bool,
}

struct LiveCreationRun {
    initial_edit_ids: Vec<String>,
    bad_edit_id: String,
    invalid_validation_digest: String,
    repaired_edit_id: String,
    final_validation_digest: String,
}

impl TestDb {
    fn new() -> Self {
        let schema = format!(
            "p0013_north_star_{}_{}",
            std::process::id(),
            SCHEMA_COUNTER.fetch_add(1, Ordering::SeqCst)
        );

        let issuer = IdentityFixtureV1::deterministic().issuer_configuration;
        let config = ServerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            WS_ID.parse().unwrap(),
            issuer,
            "deployment-secret:proof-oidc-client",
            [0x5a; 32],
            dsn(),
        )
        .with_release_signer(Ed25519SigningProvider::from_secret_bytes(&[0x22_u8; 32]))
        .with_authority_signer(Ed25519SigningProvider::from_secret_bytes(&[0x11_u8; 32]));
        let state = AppState::new(config);

        let mut runtime = PgRuntime::connect(PgConfig::new(
            dsn(),
            WS_ID.parse().unwrap(),
            Duration::from_secs(60),
        ))
        .expect("connect to PostgreSQL; run scripts/dev-pg.sh");
        {
            let client = runtime.client_mut();
            client
                .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
                .unwrap();
            client
                .batch_execute(&format!("SET search_path TO \"{schema}\""))
                .unwrap();
            for ddl in ALL_TABLE_DDL {
                client.batch_execute(ddl).unwrap();
            }
            client
                .batch_execute(proof_pg::migration::SESSION_BOUNDARY_V2_DDL)
                .unwrap();
            client
                .batch_execute(proof_pg::migration::DELIVERY_STATE_V3_DDL)
                .unwrap();
            client
                .execute(
                    "INSERT INTO migration_head (
                         singleton, version, name, script_digest, phase,
                         actor, tool_version, started_at, verified_at
                      ) VALUES (1, 4, 'application-idempotency', $1, 'verified', 'test', 'test', now(), now())",
                    &[&fixed_digest(0x10).to_string()],
                )
                .unwrap();
            client
                .execute(
                    "INSERT INTO workspace_write_head (
                         singleton, workspace_id, migration_version,
                         transaction_sequence, authority_sequence, content_sequence, release_sequence,
                         authority_head_digest, authority_head_sequence,
                         content_head_digest, release_head_digest, policy_head_digest,
                         configuration_head_digest
                      ) VALUES (1, $1, 4, 0, 10, 0, 0, $2, 10, NULL, NULL, NULL, NULL)",
                    &[&WS_ID, &fixed_digest(0xaa).to_string()],
                )
                .unwrap();
        }
        *state.pg.lock().unwrap() = Some(runtime);

        let mut session_runtime = PgRuntime::connect(PgConfig::new(
            dsn(),
            WS_ID.parse().unwrap(),
            Duration::from_secs(60),
        ))
        .expect("connect session runtime");
        session_runtime
            .client_mut()
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .unwrap();
        state.sessions.attach(session_runtime).unwrap();

        let mut cleanup = PgRuntime::connect(PgConfig::new(
            dsn(),
            WS_ID.parse().unwrap(),
            Duration::from_secs(60),
        ))
        .expect("connect cleanup connection");
        cleanup
            .client_mut()
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .unwrap();

        Self {
            state,
            cleanup: std::sync::Mutex::new(cleanup),
            schema,
        }
    }

    fn seed_fact(
        &self,
        fact_id: &str,
        fact_kind: &str,
        fact_digest: &ContentDigest,
        body: &[u8],
        auth_seq: i64,
    ) {
        let mut guard = self.cleanup.lock().unwrap();
        guard
            .client_mut()
            .execute(
                "INSERT INTO facts (fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at)
                 VALUES ($1, $2, $3, $4, $5, $6, now())",
                &[
                    &fact_id,
                    &WS_ID,
                    &fact_kind,
                    &auth_seq,
                    &fact_digest.to_string(),
                    &body,
                ],
            )
            .unwrap();
    }

    fn seed_artifact(&self, kind: &str, digest_value: &ContentDigest, bytes: &[u8]) {
        let mut guard = self.cleanup.lock().unwrap();
        guard
            .client_mut()
            .execute(
                "INSERT INTO artifact_body_pg (kind, digest, body, committed_at)
                 VALUES ($1, $2, $3, clock_timestamp())",
                &[&kind, &digest_value.to_string(), &bytes],
            )
            .unwrap();
    }

    fn seed_authority_root(&self, key_id: &str) {
        let body = canonicalize(&json!({
            "api_version": "proof.dev/workspace-authority-root/v1",
            "workspace_id": WS_ID,
            "authority_key_id": key_id,
        }))
        .unwrap();
        self.seed_fact(
            "workspace_authority_root",
            "workspace_authority_root",
            &fixed_digest(0x20),
            body.as_bytes(),
            0,
        );
    }

    fn delivery_status(&self, event_id: &str, delivery_id: &str, generation: i64) -> String {
        let mut guard = self.cleanup.lock().unwrap();
        guard
            .client_mut()
            .query_one(
                "SELECT status FROM delivery_state
                 WHERE event_id = $1 AND delivery_id = $2 AND generation = $3",
                &[&event_id, &delivery_id, &generation],
            )
            .unwrap()
            .get(0)
    }

    fn release_delivery(&self) -> ReleaseDeliveryRow {
        let mut guard = self.cleanup.lock().unwrap();
        let rows = guard
            .client_mut()
            .query(
                "SELECT o.event_id, d.delivery_id, o.workspace_transaction_sequence, o.ordinal,
                        o.ordering_key, o.stream_sequence, o.effect_digest, o.payload_digest,
                        o.artifact_kind, o.artifact_digest,
                        o.destination_configuration_version, o.destination_configuration_digest,
                        o.correlation_id, d.status, d.next_attempt_at IS NOT NULL
                 FROM outbox_events AS o
                 JOIN delivery_state AS d ON d.event_id = o.event_id AND d.generation = 1
                 WHERE o.event_type = 'preview.release' AND o.event_version = 'v1'",
                &[],
            )
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "Release commits exactly one initial delivery"
        );
        let row = &rows[0];
        ReleaseDeliveryRow {
            event_id: row.get(0),
            delivery_id: row.get(1),
            workspace_transaction_sequence: row.get(2),
            ordinal: row.get(3),
            ordering_key: row.get(4),
            stream_sequence: row.get(5),
            effect_digest: row.get(6),
            payload_digest: row.get(7),
            artifact_kind: row.get(8),
            artifact_digest: row.get(9),
            destination_configuration_version: row.get(10),
            destination_configuration_digest: row.get(11),
            correlation_id: row.get(12),
            status: row.get(13),
            next_attempt_scheduled: row.get(14),
        }
    }

    fn read_export_capture_bytes(&self, export_id: &str) -> Vec<u8> {
        let row = self
            .cleanup
            .lock()
            .unwrap()
            .client_mut()
            .query_one(
                "SELECT body FROM facts WHERE fact_id = $1 AND fact_kind = 'evidence_export_capture'",
                &[&format!("evidence_export_capture/{export_id}")],
            )
            .unwrap();
        row.get(0)
    }

    fn read_fact_bytes(&self, fact_id: &str) -> Vec<u8> {
        self.cleanup
            .lock()
            .unwrap()
            .client_mut()
            .query_one("SELECT body FROM facts WHERE fact_id = $1", &[&fact_id])
            .unwrap()
            .get(0)
    }

    fn read_fact_value(&self, fact_id: &str) -> Value {
        serde_json::from_slice(&self.read_fact_bytes(fact_id)).unwrap()
    }

    fn read_fact_rows(&self, fact_kind: &str, fact_id_pattern: &str) -> Vec<Vec<u8>> {
        self.cleanup
            .lock()
            .unwrap()
            .client_mut()
            .query(
                "SELECT body FROM facts
                 WHERE fact_kind = $1 AND fact_id LIKE $2 ORDER BY fact_id",
                &[&fact_kind, &fact_id_pattern],
            )
            .unwrap()
            .into_iter()
            .map(|row| row.get(0))
            .collect()
    }

    fn read_artifact_bytes(&self, kind: &str, digest_value: ContentDigest) -> Vec<u8> {
        self.cleanup
            .lock()
            .unwrap()
            .client_mut()
            .query_one(
                "SELECT body FROM artifact_body_pg WHERE kind = $1 AND digest = $2",
                &[&kind, &digest_value.to_string()],
            )
            .unwrap()
            .get(0)
    }

    fn assert_creation_lifecycle(&self, expected_input: &Value, live: &LiveCreationRun) {
        let mut guard = self.cleanup.lock().unwrap();
        let client = guard.client_mut();
        let native_edits = client
            .query(
                "SELECT body FROM facts
                 WHERE fact_kind = 'localized_edit' AND fact_id LIKE $1
                 ORDER BY fact_id",
                &[&format!("localized_edit/{CHANGES_ET_ID}/%")],
            )
            .unwrap();
        let edits = native_edits
            .iter()
            .map(|row| {
                let body: Vec<u8> = row.get(0);
                serde_json::from_slice::<Value>(&body).unwrap()
            })
            .collect::<Vec<_>>();
        let mut expected_kinds = expected_input["edits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edit| edit["kind"].as_str().unwrap())
            .collect::<Vec<_>>();
        expected_kinds.push("object.locale.put");
        let edit_kinds = edits
            .iter()
            .map(|edit| edit["kind"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(edit_kinds, expected_kinds);
        assert_eq!(edits.len(), 7, "six initial edits plus one repair attempt");
        assert_eq!(
            edits[..6]
                .iter()
                .map(|edit| edit["edit_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            live.initial_edit_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );
        assert_eq!(edits[6]["edit_id"], live.repaired_edit_id);
        assert_eq!(edits[6]["supersedes_edit_id"], live.bad_edit_id);
        assert_eq!(
            edits[6]["repair_of_validation_result_digest"],
            live.invalid_validation_digest
        );

        let committed_objects: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM facts
                 WHERE fact_kind = 'object'
                   AND (fact_id LIKE $1 OR fact_id LIKE $2)",
                &[
                    &format!("%{CREATED_OBJECT_A_ID}%"),
                    &format!("%{CREATED_OBJECT_B_ID}%"),
                ],
            )
            .unwrap()
            .get(0);
        assert_eq!(committed_objects, 2, "exactly two Objects commit");
        let rendition_rows = client
            .query(
                "SELECT body FROM facts
                 WHERE fact_kind = 'rendition'
                   AND (fact_id LIKE $1 OR fact_id LIKE $2)
                 ORDER BY fact_id",
                &[
                    &format!("%{CREATED_OBJECT_A_ID}%"),
                    &format!("%{CREATED_OBJECT_B_ID}%"),
                ],
            )
            .unwrap()
            .into_iter()
            .map(|row| {
                let body: Vec<u8> = row.get(0);
                serde_json::from_slice::<Value>(&body).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(rendition_rows.len(), 4, "both Objects commit both locales");
        let rendition_targets = rendition_rows
            .iter()
            .map(|rendition| {
                (
                    rendition["object_id"].as_str().unwrap(),
                    rendition["locale"].as_str().unwrap(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            rendition_targets,
            BTreeSet::from([
                (CREATED_OBJECT_A_ID, EN_LOCALE),
                (CREATED_OBJECT_A_ID, FR_CA_LOCALE),
                (CREATED_OBJECT_B_ID, EN_LOCALE),
                (CREATED_OBJECT_B_ID, FR_CA_LOCALE),
            ])
        );
        let committed_edit_ids = rendition_rows
            .iter()
            .map(|rendition| rendition["edit_id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert!(!committed_edit_ids.contains(live.bad_edit_id.as_str()));
        assert!(committed_edit_ids.contains(live.repaired_edit_id.as_str()));

        let content_sequence: i64 = client
            .query_one(
                "SELECT content_sequence FROM workspace_write_head WHERE singleton = 1",
                &[],
            )
            .unwrap()
            .get(0);
        assert_eq!(
            u64::try_from(content_sequence).unwrap(),
            TARGET_CONTENT_SEQUENCE,
            "only the six effective edits advance content sequence"
        );

        let validations = client
            .query(
                "SELECT body FROM facts
                 WHERE fact_kind = 'localized_validation' AND fact_id LIKE $1
                 ORDER BY fact_id",
                &[&format!("localized_validation/{CHANGES_ET_ID}/%")],
            )
            .unwrap()
            .into_iter()
            .map(|row| {
                let body: Vec<u8> = row.get(0);
                serde_json::from_slice::<Value>(&body).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(validations.len(), 2);
        assert_eq!(validations[0]["valid"], false);
        assert_eq!(
            validations[0]["results_digest"],
            live.invalid_validation_digest
        );
        assert_eq!(validations[0]["findings"].as_array().unwrap().len(), 1);
        assert_eq!(
            validations[0]["findings"][0]["code"],
            "proof.validation.prohibited_legal_claim"
        );
        assert_eq!(validations[0]["findings"][0]["edit_id"], live.bad_edit_id);
        assert_eq!(validations[0]["findings"][0]["locale"], FR_CA_LOCALE);
        assert_eq!(validations[0]["findings"][0]["pointer"], "/legal");
        assert_eq!(validations[1]["valid"], true);
        assert_eq!(validations[1]["findings"], json!([]));
        assert_eq!(
            validations[1]["results_digest"],
            live.final_validation_digest
        );
        assert_eq!(
            validations[1]["previous_result_digest"],
            live.invalid_validation_digest
        );

        let consequences = client
            .query(
                "SELECT body FROM application_consequences
                 WHERE operation = 'changeset.add' ORDER BY committed_at",
                &[],
            )
            .unwrap()
            .into_iter()
            .map(|row| {
                let body: Vec<u8> = row.get(0);
                serde_json::from_slice::<RemoteApplicationConsequenceV1>(&body).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(consequences.len(), 4);
        assert_eq!(
            consequences[0].outcome,
            ApplicationConsequenceOutcome::Success
        );
        assert_eq!(
            consequences[1].outcome,
            ApplicationConsequenceOutcome::IdempotentReplay
        );
        assert_eq!(
            consequences[2].outcome,
            ApplicationConsequenceOutcome::IdempotencyConflict
        );
        assert_eq!(
            consequences[3].outcome,
            ApplicationConsequenceOutcome::Success
        );
        assert!(consequences[..3].iter().all(|consequence| {
            consequence.application_key_kind == ApplicationKeyKind::RequiredUuidV7
                && consequence.application_key.as_deref()
                    == expected_input["idempotency_key"].as_str()
        }));
        assert_eq!(
            consequences[3].application_key.as_deref(),
            Some(REPAIR_ADD_APPLICATION_KEY)
        );
    }

    fn producer_input_snapshot(&self) -> ProducerInputSnapshot {
        let mut guard = self.cleanup.lock().unwrap();
        let client = guard.client_mut();
        let facts = client
            .query(
                "SELECT fact_id, fact_kind, authority_sequence, fact_digest, body
                 FROM facts WHERE fact_kind <> 'release_export_material'
                 ORDER BY fact_id",
                &[],
            )
            .unwrap()
            .into_iter()
            .map(|row| ProducerInputFact {
                fact_id: row.get(0),
                fact_kind: row.get(1),
                authority_sequence: row.get(2),
                fact_digest: row.get(3),
                body: row.get(4),
            })
            .collect();
        let head = client
            .query_one(
                "SELECT transaction_sequence, authority_sequence, content_sequence,
                        release_sequence, authority_head_digest, content_head_digest,
                        release_head_digest
                 FROM workspace_write_head WHERE singleton = 1",
                &[],
            )
            .unwrap();
        ProducerInputSnapshot {
            facts,
            transaction_sequence: head.get(0),
            authority_sequence: head.get(1),
            content_sequence: head.get(2),
            release_sequence: head.get(3),
            authority_head_digest: head.get(4),
            content_head_digest: head.get(5),
            release_head_digest: head.get(6),
        }
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.cleanup.lock() {
            let _ = guard
                .client_mut()
                .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema));
        }
    }
}

// ---------------------------------------------------------------------------
// Bootstrap identity seeding (verified pre-existing Workspace inputs).
// ---------------------------------------------------------------------------

struct HumanIdentity {
    subject_commitment: ContentDigest,
}

fn seed_human_identity(
    db: &TestDb,
    principal_id: &'static str,
    binding_id: &'static str,
    subject_label: &'static str,
    auth_seq: i64,
) -> HumanIdentity {
    let subject = OidcAuthenticatedSubjectV1 {
        api_version: OidcAuthenticatedSubjectApiVersion::V1,
        issuer: "https://identity.example.test".to_owned(),
        provider: "proof/oidc".to_owned(),
        subject: subject_label.to_owned(),
    };
    let blind = [0x42_u8; 32];
    let commitment_input = OidcSubjectCommitmentInputV1 {
        api_version: OidcSubjectCommitmentInputApiVersion::V1,
        blind: encode_blind(&blind),
        subject: subject.clone(),
        workspace_id: WS_ID.to_owned(),
    };
    let subject_commitment = subject_commitment_digest(&commitment_input).unwrap();
    let opening = OidcSubjectCommitmentOpeningV1 {
        api_version: OidcSubjectCommitmentOpeningApiVersion::V1,
        commitment: subject_commitment,
        input: commitment_input,
    };

    let issuer_configuration_digest = IdentityFixtureV1::deterministic()
        .issuer_configuration
        .digest()
        .unwrap();

    let public = OidcPrincipalBindingV1 {
        api_version: OidcPrincipalBindingApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        binding_id: binding_id.to_owned(),
        principal_id: principal_id.to_owned(),
        subject_commitment,
        oidc_issuer_configuration_digest: issuer_configuration_digest,
        issued_by_principal_id: H1_REQUESTER.to_owned(),
        issued_at: now_timestamp(),
        supersedes_binding_id: None,
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: 1,
            record_digest: fixed_digest(0x01),
        },
        authority_sequence: u64::try_from(auth_seq).unwrap(),
        previous_authority_record_digest: fixed_digest(0x01),
        authority_key_id:
            "ed25519:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
    };

    let binding_record_digest = public.binding_record_digest().unwrap();
    let private = OidcPrincipalBindingPrivateV1 {
        api_version: OidcPrincipalBindingPrivateApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        binding_id: binding_id.to_owned(),
        principal_id: principal_id.to_owned(),
        subject,
        subject_commitment,
        opening,
        oidc_issuer_configuration_digest: issuer_configuration_digest,
        binding_record_digest,
    };

    let public_body = canonicalize(&serde_json::to_value(&public).unwrap()).unwrap();
    db.seed_fact(
        &format!("oidc_binding/{binding_id}"),
        "oidc_public_binding",
        &binding_record_digest,
        public_body.as_bytes(),
        auth_seq,
    );
    let private_body = canonicalize(&serde_json::to_value(&private).unwrap()).unwrap();
    let private_digest = ContentDigest::blake3(*blake3::hash(private_body.as_bytes()).as_bytes());
    db.seed_fact(
        &format!("oidc_private_binding/{binding_id}"),
        "oidc_private_binding",
        &private_digest,
        private_body.as_bytes(),
        auth_seq,
    );

    HumanIdentity { subject_commitment }
}

fn seed_principal_status(db: &TestDb, principal_id: &str, agent: bool, auth_seq: i64) {
    let status = proof_remote::authority::RemotePrincipalStatusV2 {
        api_version: proof_remote::authority::RemotePrincipalStatusApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        principal_id: principal_id.to_owned(),
        principal_type: if agent {
            proof_remote::authority::RemotePrincipalType::Agent
        } else {
            proof_remote::authority::RemotePrincipalType::Human
        },
        enabled: true,
        reason: "north-star bootstrap".to_owned(),
        recorded_by_principal_id: H1_REQUESTER.to_owned(),
        recorded_by_actor_context_digest: fixed_digest(0x30),
        recorded_at: now_timestamp(),
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: 1,
            record_digest: fixed_digest(0x01),
        },
        authority_sequence: u64::try_from(auth_seq).unwrap(),
        previous_authority_record_digest: fixed_digest(0x01),
        authority_key_id:
            "ed25519:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
    };
    let body = canonicalize(&serde_json::to_value(&status).unwrap()).unwrap();
    db.seed_fact(
        &format!("principal_status/{principal_id}"),
        "principal_status",
        &RemoteAuthorityRecordV1::principal_status(status).digest(),
        body.as_bytes(),
        auth_seq,
    );
}

fn seed_role_assignment(
    db: &TestDb,
    principal_id: &str,
    role: proof_remote::authority::WorkspaceRole,
    assignment_suffix: u8,
) {
    use proof_remote::authority::{WorkspaceRoleAssignmentApiVersion, WorkspaceRoleAssignmentV1};
    let assignment_id = format!("019c0000-0000-7000-8000-0000000007{assignment_suffix:02}");
    let assignment = WorkspaceRoleAssignmentV1 {
        api_version: WorkspaceRoleAssignmentApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        assignment_id: assignment_id.clone(),
        principal_id: principal_id.to_owned(),
        role,
        assigned_by_principal_id: H1_REQUESTER.to_owned(),
        assigned_by_actor_context_digest: fixed_digest(0x32),
        assigned_at: now_timestamp(),
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: 1,
            record_digest: fixed_digest(0x01),
        },
        authority_sequence: 4,
        previous_authority_record_digest: fixed_digest(0x01),
        authority_key_id:
            "ed25519:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
    };
    let body = canonicalize(&serde_json::to_value(&assignment).unwrap()).unwrap();
    db.seed_fact(
        &format!("workspace_role_assignment/{assignment_id}"),
        "workspace_role_assignment",
        &RemoteAuthorityRecordV1::workspace_role_assignment(assignment).digest(),
        body.as_bytes(),
        4,
    );
}

fn seed_live_agent_binding(
    db: &TestDb,
    agent_provider: &Ed25519SigningProvider,
    authority_provider: &Ed25519SigningProvider,
) {
    let metadata = agent_provider.metadata().unwrap();
    let key_id = Ed25519KeyId::new(metadata.key_id.clone()).unwrap();
    let public_key = Ed25519PublicKey::new(BASE64.encode(&metadata.public_key)).unwrap();
    let mut guard = db.cleanup.lock().unwrap();
    let client = guard.client_mut();
    let head = client
        .query_one(
            "SELECT authority_head_sequence, authority_head_digest
             FROM workspace_write_head WHERE singleton = 1",
            &[],
        )
        .unwrap();
    let previous_sequence = u64::try_from(head.get::<_, i64>(0)).unwrap();
    let previous_digest: ContentDigest = head.get::<_, String>(1).parse().unwrap();
    let authority_sequence = previous_sequence.checked_add(1).unwrap();

    let binding = PrincipalBindingV1 {
        api_version: PrincipalBindingApiVersion::V1,
        authority_sequence: AuthoritySequence::new(authority_sequence).unwrap(),
        previous_authority_record_digest: Some(previous_digest),
        workspace_id: WS_ID.parse().unwrap(),
        binding_id: AGENT_BINDING_ID.parse().unwrap(),
        principal_id: G_OPERATOR.parse().unwrap(),
        principal_type: AgentPrincipalType::Agent,
        authenticated_subject: LocalEd25519AuthenticatedSubjectV1::new(&key_id),
        algorithm: Ed25519Algorithm::Ed25519,
        public_key,
        key_usage: AuthenticatedCommandKeyUsage::AuthenticatedCommand,
        audience: AuthorityAudience::for_workspace(WS_ID.parse().unwrap()),
        enrollment_challenge_digest: fixed_digest(0x33),
        enrollment_envelope_digest: fixed_digest(0x34),
        issued_by_principal_id: H1_REQUESTER.parse().unwrap(),
        issued_at: timestamp_offset(-60),
        not_before: timestamp_offset(-60),
        expires_at: timestamp_offset(86_400),
        supersedes_binding_id: None,
    };
    let body = canonicalize(&serde_json::to_value(&binding).unwrap()).unwrap();
    let signed = proof_remote::sign_remote_authority_record(
        &RemoteAuthorityRecordV1::agent_binding_issue(binding),
        authority_provider,
    )
    .unwrap();
    let sequence = i64::try_from(authority_sequence).unwrap();
    client
        .execute(
            "INSERT INTO facts (
                 fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at
             ) VALUES ($1, $2, 'agent_binding', $3, $4, $5, now())",
            &[
                &format!("agent_binding/{AGENT_BINDING_ID}"),
                &WS_ID,
                &sequence,
                &signed.payload_digest.to_string(),
                &body.as_bytes(),
            ],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO remote_authority_records (
                 authority_sequence, workspace_id, record_digest, envelope_digest,
                 payload_type, envelope, predecessor_digest, committed_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, now())",
            &[
                &sequence,
                &WS_ID,
                &signed.payload_digest.to_string(),
                &signed.envelope_digest.to_string(),
                &proof_remote::REMOTE_AUTHORITY_RECORD_PAYLOAD_TYPE,
                &signed.envelope_json.as_bytes(),
                &previous_digest.to_string(),
            ],
        )
        .unwrap();
    client
        .execute(
            "UPDATE workspace_write_head
             SET authority_sequence = $1, authority_head_sequence = $1,
                 authority_head_digest = $2
             WHERE singleton = 1",
            &[&sequence, &signed.payload_digest.to_string()],
        )
        .unwrap();
}

#[derive(Clone)]
struct FixtureArtifact {
    kind: ArtifactKind,
    digest: ContentDigest,
    bytes: Vec<u8>,
}

fn fixture_artifact(_role: &'static str, kind: ArtifactKind, value: &Value) -> FixtureArtifact {
    let bytes = canonical_bytes(value);
    let digest = artifact_digest(kind, &bytes);
    FixtureArtifact {
        kind,
        digest,
        bytes,
    }
}

#[derive(Clone)]
struct CreationFixture {
    artifacts: Vec<FixtureArtifact>,
    resource_intent: Value,
    context_pack: Value,
    expected_add_input: Value,
}

fn dsse_envelope(key: &SigningKey, key_id: &str, statement: &Value) -> Value {
    let payload = canonical_bytes(statement);
    let payload_type = "application/vnd.in-toto+json";
    let prefix = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut pae = Vec::with_capacity(prefix.len() + payload.len());
    pae.extend_from_slice(prefix.as_bytes());
    pae.extend_from_slice(&payload);
    json!({
        "payload": BASE64.encode(payload),
        "payloadType": payload_type,
        "signatures": [{
            "keyid": key_id,
            "sig": BASE64.encode(key.sign(&pae).to_bytes()),
        }],
    })
}

fn digest_hex(digest_value: &ContentDigest) -> String {
    digest_value
        .to_string()
        .strip_prefix("blake3:")
        .unwrap()
        .to_owned()
}

#[allow(clippy::too_many_lines)]
fn build_creation_fixture(
    release_key: &SigningKey,
    release_key_id: &str,
    environment_digest: ContentDigest,
) -> CreationFixture {
    let mut artifacts = Vec::new();
    let mut add = |role, kind, value: &Value| {
        let artifact = fixture_artifact(role, kind, value);
        artifacts.push(artifact.clone());
        artifact
    };

    let schema_a = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": false,
        "properties": {
            "legal": {"type": "string"},
            "title": {"type": "string"},
        },
        "required": ["legal", "title"],
        "title": "Article",
        "type": "object",
        "x-proof-localizable": ["/legal", "/title"],
    });
    let schema_b = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": false,
        "properties": {
            "legal": {"type": "string"},
            "name": {"type": "string"},
        },
        "required": ["legal", "name"],
        "title": "Product",
        "type": "object",
        "x-proof-localizable": ["/legal", "/name"],
    });
    let schema_a_ref = add("schema", ArtifactKind::SchemaVersionV1, &schema_a);
    let schema_b_ref = add("schema", ArtifactKind::SchemaVersionV1, &schema_b);
    let schema_a_state = json!({
        "document_digest": schema_a_ref.digest.to_string(),
        "schema_id": OBJECT_A_SCHEMA_ID,
        "schema_version": 1,
    });
    let schema_b_state = json!({
        "document_digest": schema_b_ref.digest.to_string(),
        "schema_id": OBJECT_B_SCHEMA_ID,
        "schema_version": 1,
    });
    let schema_set = json!({
        "api_version": "proof.dev/schema-set/v1",
        "schemas": [schema_a_state, schema_b_state],
    });
    let schema_set_digest =
        artifact_digest(ArtifactKind::SchemaSetV1, &canonical_bytes(&schema_set));
    let context_policy = json!({
        "api_version": "proof.dev/policy-bundle/v1",
        "policy_id": "proof.local/localized-content/default/v1",
        "required_approval": "editorial",
        "rules": [{
            "disallowed_values": [FORBIDDEN_LEGAL_CLAIM],
            "locale": FR_CA_LOCALE,
            "pointer": "/legal",
        }],
        "validator": "proof/localized-content/1",
    });
    let context_policy_ref = add(
        "context_policy_bundle",
        ArtifactKind::PolicyBundleV1,
        &context_policy,
    );

    let base_state = json!({
        "api_version": "proof.dev/known-state/v2",
        "authoritative_sequence": BASE_CONTENT_SEQUENCE,
        "objects": [],
        "previous_state": null,
        "renditions": [],
        "schemas": [schema_a_state, schema_b_state],
        "workspace_id": WS_ID,
    });
    let base_state_ref = add("known_state", ArtifactKind::KnownStateV2, &base_state);
    let base_state_reference = json!({
        "api_version": "proof.dev/known-state/v2",
        "authoritative_sequence": BASE_CONTENT_SEQUENCE,
        "known_state_digest": base_state_ref.digest.to_string(),
    });
    let base_object_set = json!({
        "api_version": "proof.dev/object-set/v2",
        "objects": [],
        "renditions": [],
    });
    let base_object_set_ref = add("object_set", ArtifactKind::ObjectSetV2, &base_object_set);
    let base_edition = json!({
        "api_version": "proof.dev/edition/v2",
        "authoritative_sequence": BASE_CONTENT_SEQUENCE,
        "base_edition": null,
        "changeset": null,
        "created_at": "2026-08-26T11:00:00Z",
        "edition_id": BASE_EDITION_ID,
        "object_set_digest": base_object_set_ref.digest.to_string(),
        "objects": [],
        "principal_id": H1_REQUESTER,
        "renditions": [],
        "schema_set_digest": schema_set_digest.to_string(),
        "schemas": [schema_a_state, schema_b_state],
        "state": base_state_reference,
        "workspace_id": WS_ID,
    });
    let base_edition_ref = add("edition", ArtifactKind::EditionV2, &base_edition);
    let base_edition_reference = json!({
        "api_version": "proof.dev/edition/v2",
        "edition_digest": base_edition_ref.digest.to_string(),
        "edition_id": BASE_EDITION_ID,
    });
    let base_policy_decision = json!({
        "action": "release.promote",
        "allowed": true,
        "api_version": "proof.dev/release-authorization-decision/v1",
        "delegation_chain": [],
        "edition_digest": base_edition_ref.digest.to_string(),
        "edition_id": BASE_EDITION_ID,
        "environment_config_digest": environment_digest.to_string(),
        "environment_config_version": 2,
        "environment_id": "preview",
        "evaluated_at": "2026-08-26T11:01:00Z",
        "evidence": [],
        "operating_principal_id": H1_REQUESTER,
        "policy_profile": "editorial-sod",
        "previous_release_id": null,
        "required_approval": "editorial",
        "rollback_target_release_id": null,
        "workspace_id": WS_ID,
    });
    let base_policy_ref = add(
        "release_policy_decision",
        ArtifactKind::AuthorizationDecisionV1,
        &base_policy_decision,
    );
    let base_release = json!({
        "api_version": "proof.dev/release/v1",
        "authorization_decision_digest": base_policy_ref.digest.to_string(),
        "delegation_id": null,
        "edition_digest": base_edition_ref.digest.to_string(),
        "edition_id": BASE_EDITION_ID,
        "environment_config_digest": environment_digest.to_string(),
        "environment_config_version": 2,
        "environment_id": "preview",
        "key_id": release_key_id,
        "kind": "promotion",
        "previous_release_id": null,
        "principal_id": H1_REQUESTER,
        "proof_id": BASE_PROOF_ID,
        "release_id": BASE_RELEASE_ID,
        "release_sequence": 1,
        "released_at": "2026-08-26T11:01:00Z",
        "rollback_target_release_id": null,
        "workspace_id": WS_ID,
    });
    let base_release_ref = add("release_manifest", ArtifactKind::ReleaseV1, &base_release);
    let base_release_reference = json!({
        "api_version": "proof.dev/release/v1",
        "release_digest": base_release_ref.digest.to_string(),
        "release_id": BASE_RELEASE_ID,
    });
    let base_closure = json!({
        "edition": base_edition_reference,
        "known_state": base_state_reference,
        "release": base_release_reference,
    });

    let targets = json!([
        {
            "locale": EN_LOCALE,
            "object_id": CREATED_OBJECT_A_ID,
            "schema_id": OBJECT_A_SCHEMA_ID,
        },
        {
            "locale": FR_CA_LOCALE,
            "object_id": CREATED_OBJECT_A_ID,
            "schema_id": OBJECT_A_SCHEMA_ID,
        },
        {
            "locale": EN_LOCALE,
            "object_id": CREATED_OBJECT_B_ID,
            "schema_id": OBJECT_B_SCHEMA_ID,
        },
        {
            "locale": FR_CA_LOCALE,
            "object_id": CREATED_OBJECT_B_ID,
            "schema_id": OBJECT_B_SCHEMA_ID,
        }
    ]);
    let resource_intent = json!({
        "api_version": "proof.dev/content-resource-intent/v2",
        "base": base_closure,
        "creations": [
            {
                "locales": [EN_LOCALE, FR_CA_LOCALE],
                "object_id": CREATED_OBJECT_A_ID,
                "schema_id": OBJECT_A_SCHEMA_ID,
            },
            {
                "locales": [EN_LOCALE, FR_CA_LOCALE],
                "object_id": CREATED_OBJECT_B_ID,
                "schema_id": OBJECT_B_SCHEMA_ID,
            }
        ],
        "environment_id": "preview",
        "intent_id": RESOURCE_INTENT_ID,
        "issued_at": CONTENT_ISSUED_AT,
        "issued_by_principal_id": H1_REQUESTER,
        "targets": targets,
        "workspace_id": WS_ID,
    });
    let resource_intent_ref = add(
        "resource_intent",
        ArtifactKind::ContentResourceIntentV1,
        &resource_intent,
    );
    let context_pack = json!({
        "allowed_operations": [
            "proof.dev/operation/changeset.create/v2",
            "proof.dev/operation/changeset.add/v2",
            "proof.dev/operation/changeset.get/v2",
            "proof.dev/operation/changeset.diff/v2",
            "proof.dev/operation/changeset.validate/v2",
            "proof.dev/operation/changeset.submit/v2",
            "proof.dev/operation/changeset.commit/v2",
            "proof.dev/operation/edition.create/v2",
            "proof.dev/operation/release.create/v2",
            "proof.dev/operation/object.query_released/v2"
        ],
        "api_version": "proof.dev/context-pack/v2",
        "context_pack_id": CONTEXT_PACK_ID,
        "created_at": CONTEXT_CREATED_AT,
        "explicit_exclusions": [
            "agent-authority",
            "campaign-expansion",
            "deletion",
            "fallback",
            "generic-object-replacement",
            "relationship-mutation",
            "schema-mutation"
        ],
        "expires_at": CONTEXT_EXPIRES_AT,
        "limits": {
            "max_bytes": 8192,
            "max_edits": 7,
            "max_objects": 2,
            "max_validation_attempts": 2,
        },
        "policy": context_policy,
        "policy_digest": context_policy_ref.digest.to_string(),
        "principal_id": H1_REQUESTER,
        "resource_intent": resource_intent,
        "resource_intent_digest": resource_intent_ref.digest.to_string(),
        "resources": [
            {
                "locale": EN_LOCALE,
                "object_id": CREATED_OBJECT_A_ID,
                "schema_candidates": [{
                    "document": schema_a,
                    "document_digest": schema_a_ref.digest.to_string(),
                    "localizable_pointers": ["/legal", "/title"],
                    "schema_id": OBJECT_A_SCHEMA_ID,
                    "schema_version": 1,
                }],
                "source": {
                    "absent": true,
                    "api_version": "proof.dev/object-revision-absence/v1",
                    "authoritative_sequence": BASE_CONTENT_SEQUENCE,
                },
                "target": {
                    "absent": true,
                    "api_version": "proof.dev/object-locale-absence/v1",
                    "authoritative_sequence": BASE_CONTENT_SEQUENCE,
                },
            },
            {
                "locale": FR_CA_LOCALE,
                "object_id": CREATED_OBJECT_A_ID,
                "schema_candidates": [{
                    "document": schema_a,
                    "document_digest": schema_a_ref.digest.to_string(),
                    "localizable_pointers": ["/legal", "/title"],
                    "schema_id": OBJECT_A_SCHEMA_ID,
                    "schema_version": 1,
                }],
                "source": {
                    "absent": true,
                    "api_version": "proof.dev/object-revision-absence/v1",
                    "authoritative_sequence": BASE_CONTENT_SEQUENCE,
                },
                "target": {
                    "absent": true,
                    "api_version": "proof.dev/object-locale-absence/v1",
                    "authoritative_sequence": BASE_CONTENT_SEQUENCE,
                },
            },
            {
                "locale": EN_LOCALE,
                "object_id": CREATED_OBJECT_B_ID,
                "schema_candidates": [{
                    "document": schema_b,
                    "document_digest": schema_b_ref.digest.to_string(),
                    "localizable_pointers": ["/legal", "/name"],
                    "schema_id": OBJECT_B_SCHEMA_ID,
                    "schema_version": 1,
                }],
                "source": {
                    "absent": true,
                    "api_version": "proof.dev/object-revision-absence/v1",
                    "authoritative_sequence": BASE_CONTENT_SEQUENCE,
                },
                "target": {
                    "absent": true,
                    "api_version": "proof.dev/object-locale-absence/v1",
                    "authoritative_sequence": BASE_CONTENT_SEQUENCE,
                },
            },
            {
                "locale": FR_CA_LOCALE,
                "object_id": CREATED_OBJECT_B_ID,
                "schema_candidates": [{
                    "document": schema_b,
                    "document_digest": schema_b_ref.digest.to_string(),
                    "localizable_pointers": ["/legal", "/name"],
                    "schema_id": OBJECT_B_SCHEMA_ID,
                    "schema_version": 1,
                }],
                "source": {
                    "absent": true,
                    "api_version": "proof.dev/object-revision-absence/v1",
                    "authoritative_sequence": BASE_CONTENT_SEQUENCE,
                },
                "target": {
                    "absent": true,
                    "api_version": "proof.dev/object-locale-absence/v1",
                    "authoritative_sequence": BASE_CONTENT_SEQUENCE,
                },
            }
        ],
        "target_ordering": "object_id,schema_id,locale:utf8-ascending",
        "validator": "proof/localized-content/1",
        "workspace_id": WS_ID,
    });
    let context_pack_ref = add("context_pack", ArtifactKind::ContextPackV2, &context_pack);

    let create_a_edit = json!({
        "api_version": "proof.dev/edit/v2",
        "content": {
            "legal": "Standard terms apply",
            "title": "Canonical article",
        },
        "edit_id": CREATE_A_EDIT_ID,
        "kind": "object.create",
        "object_id": CREATED_OBJECT_A_ID,
        "repair_of_validation_result_digest": null,
        "schema_id": OBJECT_A_SCHEMA_ID,
        "schema_version": 1,
        "supersedes_edit_id": null,
    });
    let create_a_ref = add("edit", ArtifactKind::ObjectCreateEditV2, &create_a_edit);
    let create_a_source_digest = object_revision_digest(
        CREATED_OBJECT_A_ID.parse().unwrap(),
        &proof_domain::SchemaId::new(OBJECT_A_SCHEMA_ID).unwrap(),
        proof_domain::SchemaVersion::new(1).unwrap(),
        &create_a_edit["content"],
    )
    .unwrap();
    let put_a_edit = json!({
        "api_version": "proof.dev/edit/v2",
        "content": {
            "legal": "Standard terms apply",
            "title": "Published article",
        },
        "edit_id": PUT_A_EDIT_ID,
        "expected_source": {
            "digest": create_a_source_digest.to_string(),
            "revision": 1,
            "schema_id": OBJECT_A_SCHEMA_ID,
            "schema_version": 1,
        },
        "expected_target": null,
        "kind": "object.locale.put",
        "locale": EN_LOCALE,
        "object_id": CREATED_OBJECT_A_ID,
        "repair_of_validation_result_digest": null,
        "supersedes_edit_id": null,
    });
    let put_a_ref = add("edit", ArtifactKind::EditV2, &put_a_edit);
    let create_b_edit = json!({
        "api_version": "proof.dev/edit/v2",
        "content": {
            "legal": "Standard terms apply",
            "name": "Canonical product",
        },
        "edit_id": CREATE_B_EDIT_ID,
        "kind": "object.create",
        "object_id": CREATED_OBJECT_B_ID,
        "repair_of_validation_result_digest": null,
        "schema_id": OBJECT_B_SCHEMA_ID,
        "schema_version": 1,
        "supersedes_edit_id": null,
    });
    let create_b_ref = add("edit", ArtifactKind::ObjectCreateEditV2, &create_b_edit);
    let create_b_source_digest = object_revision_digest(
        CREATED_OBJECT_B_ID.parse().unwrap(),
        &proof_domain::SchemaId::new(OBJECT_B_SCHEMA_ID).unwrap(),
        proof_domain::SchemaVersion::new(1).unwrap(),
        &create_b_edit["content"],
    )
    .unwrap();
    let put_b_edit = json!({
        "api_version": "proof.dev/edit/v2",
        "content": {
            "legal": "Des conditions standard s'appliquent",
            "name": "Produit publie",
        },
        "edit_id": PUT_B_EDIT_ID,
        "expected_source": {
            "digest": create_b_source_digest.to_string(),
            "revision": 1,
            "schema_id": OBJECT_B_SCHEMA_ID,
            "schema_version": 1,
        },
        "expected_target": null,
        "kind": "object.locale.put",
        "locale": FR_CA_LOCALE,
        "object_id": CREATED_OBJECT_B_ID,
        "repair_of_validation_result_digest": null,
        "supersedes_edit_id": null,
    });
    let put_b_ref = add("edit", ArtifactKind::EditV2, &put_b_edit);
    let edits = vec![
        create_a_edit.clone(),
        put_a_edit.clone(),
        create_b_edit.clone(),
        put_b_edit.clone(),
    ];
    let effective_batch = json!({
        "api_version": "proof.dev/edit-batch/v2",
        "edits": edits,
    });
    let effective_batch_ref = add("edit", ArtifactKind::EditBatchV2, &effective_batch);
    let effective_leaves = json!([
        {
            "edit_digest": create_a_ref.digest.to_string(),
            "edit_id": CREATE_A_EDIT_ID,
            "object_id": CREATED_OBJECT_A_ID,
        },
        {
            "edit_digest": put_a_ref.digest.to_string(),
            "edit_id": PUT_A_EDIT_ID,
            "locale": EN_LOCALE,
            "object_id": CREATED_OBJECT_A_ID,
        },
        {
            "edit_digest": create_b_ref.digest.to_string(),
            "edit_id": CREATE_B_EDIT_ID,
            "object_id": CREATED_OBJECT_B_ID,
        },
        {
            "edit_digest": put_b_ref.digest.to_string(),
            "edit_id": PUT_B_EDIT_ID,
            "locale": FR_CA_LOCALE,
            "object_id": CREATED_OBJECT_B_ID,
        }
    ]);
    let changeset = json!({
        "api_version": "proof.dev/changeset/v2",
        "base_state": base_state_reference,
        "changeset_id": CHANGES_ET_ID,
        "context_pack_digest": context_pack_ref.digest.to_string(),
        "context_pack_id": CONTEXT_PACK_ID,
        "created_at": CHANGESET_CREATED_AT,
        "edits": edits,
        "effective_leaf_digest": effective_batch_ref.digest.to_string(),
        "effective_leaves": effective_leaves,
        "intent": "Create two localized resources",
        "principal_id": H1_REQUESTER,
        "resource_intent_digest": resource_intent_ref.digest.to_string(),
        "resource_intent_id": RESOURCE_INTENT_ID,
        "workspace_id": WS_ID,
    });
    let changeset_ref = add("changeset", ArtifactKind::ChangeSetV2, &changeset);
    let validation = json!({
        "api_version": "proof.dev/validation-results/v2",
        "attempt": 1,
        "changeset_id": CHANGES_ET_ID,
        "context_pack_digest": context_pack_ref.digest.to_string(),
        "effective_leaf_digest": effective_batch_ref.digest.to_string(),
        "findings": [],
        "policy_digest": context_policy_ref.digest.to_string(),
        "previous_validation_result_digest": null,
        "proposal_digest": changeset_ref.digest.to_string(),
        "schema_digests": [schema_a_state, schema_b_state],
        "valid": true,
        "validator": "proof/localized-content/1",
    });
    let validation_ref = add(
        "validation_attempt",
        ArtifactKind::ValidationResultsV2,
        &validation,
    );
    let seal = json!({
        "api_version": "proof.dev/changeset-seal/v2",
        "proposal_digest": changeset_ref.digest.to_string(),
        "validation_results_digest": validation_ref.digest.to_string(),
    });
    let seal_ref = add("changeset", ArtifactKind::ChangeSetV2, &seal);

    let object_a_state = json!({
        "lifecycle_state": "active",
        "object_digest": create_a_ref.digest.to_string(),
        "object_id": CREATED_OBJECT_A_ID,
        "revision": 1,
        "schema_id": OBJECT_A_SCHEMA_ID,
        "schema_version": 1,
    });
    let object_b_state = json!({
        "lifecycle_state": "active",
        "object_digest": create_b_ref.digest.to_string(),
        "object_id": CREATED_OBJECT_B_ID,
        "revision": 1,
        "schema_id": OBJECT_B_SCHEMA_ID,
        "schema_version": 1,
    });
    let rendition_a = json!({
        "api_version": "proof.dev/object-locale-revision/v1",
        "authoritative_sequence": TARGET_CONTENT_SEQUENCE,
        "changeset_id": CHANGES_ET_ID,
        "content": {"title": "Published article"},
        "edit_id": PUT_A_EDIT_ID,
        "locale": EN_LOCALE,
        "object_id": CREATED_OBJECT_A_ID,
        "previous_revision_digest": null,
        "revision": 1,
        "schema_id": OBJECT_A_SCHEMA_ID,
        "schema_version": 1,
        "source_object_digest": create_a_ref.digest.to_string(),
        "source_object_revision": 1,
        "workspace_id": WS_ID,
    });
    let rendition_a_ref = add(
        "locale_revision",
        ArtifactKind::ObjectLocaleRevisionV1,
        &rendition_a,
    );
    let rendition_b = json!({
        "api_version": "proof.dev/object-locale-revision/v1",
        "authoritative_sequence": TARGET_CONTENT_SEQUENCE,
        "changeset_id": CHANGES_ET_ID,
        "content": {"name": "Produit publie"},
        "edit_id": PUT_B_EDIT_ID,
        "locale": FR_CA_LOCALE,
        "object_id": CREATED_OBJECT_B_ID,
        "previous_revision_digest": null,
        "revision": 1,
        "schema_id": OBJECT_B_SCHEMA_ID,
        "schema_version": 1,
        "source_object_digest": create_b_ref.digest.to_string(),
        "source_object_revision": 1,
        "workspace_id": WS_ID,
    });
    let rendition_b_ref = add(
        "locale_revision",
        ArtifactKind::ObjectLocaleRevisionV1,
        &rendition_b,
    );
    let rendition_a_state = json!({
        "locale": EN_LOCALE,
        "object_id": CREATED_OBJECT_A_ID,
        "rendition_digest": rendition_a_ref.digest.to_string(),
        "revision": 1,
        "schema_id": OBJECT_A_SCHEMA_ID,
        "schema_version": 1,
        "source_object_digest": create_a_ref.digest.to_string(),
    });
    let rendition_b_state = json!({
        "locale": FR_CA_LOCALE,
        "object_id": CREATED_OBJECT_B_ID,
        "rendition_digest": rendition_b_ref.digest.to_string(),
        "revision": 1,
        "schema_id": OBJECT_B_SCHEMA_ID,
        "schema_version": 1,
        "source_object_digest": create_b_ref.digest.to_string(),
    });
    let target_state = json!({
        "api_version": "proof.dev/known-state/v2",
        "authoritative_sequence": TARGET_CONTENT_SEQUENCE,
        "objects": [object_a_state, object_b_state],
        "previous_state": base_state_reference,
        "renditions": [rendition_a_state, rendition_b_state],
        "schemas": [schema_a_state, schema_b_state],
        "workspace_id": WS_ID,
    });
    let target_state_ref = add("known_state", ArtifactKind::KnownStateV2, &target_state);
    let target_state_reference = json!({
        "api_version": "proof.dev/known-state/v2",
        "authoritative_sequence": TARGET_CONTENT_SEQUENCE,
        "known_state_digest": target_state_ref.digest.to_string(),
    });
    let changeset_evidence = json!({
        "changeset_id": CHANGES_ET_ID,
        "context_pack_digest": context_pack_ref.digest.to_string(),
        "effective_leaf_digest": effective_batch_ref.digest.to_string(),
        "proposal_digest": changeset_ref.digest.to_string(),
        "resource_intent_digest": resource_intent_ref.digest.to_string(),
        "sealed_changeset_digest": seal_ref.digest.to_string(),
        "validation_results_digest": validation_ref.digest.to_string(),
    });
    let target_object_set = json!({
        "api_version": "proof.dev/object-set/v2",
        "objects": [object_a_state, object_b_state],
        "renditions": [rendition_a_state, rendition_b_state],
    });
    let target_object_set_ref = add("object_set", ArtifactKind::ObjectSetV2, &target_object_set);
    let target_edition = json!({
        "api_version": "proof.dev/edition/v2",
        "authoritative_sequence": TARGET_CONTENT_SEQUENCE,
        "base_edition": base_edition_reference,
        "changeset": changeset_evidence,
        "created_at": EDITION_CREATED_AT,
        "edition_id": EDITION_ID,
        "object_set_digest": target_object_set_ref.digest.to_string(),
        "objects": [object_a_state, object_b_state],
        "principal_id": H2_APPROVER,
        "renditions": [rendition_a_state, rendition_b_state],
        "schema_set_digest": schema_set_digest.to_string(),
        "schemas": [schema_a_state, schema_b_state],
        "state": target_state_reference,
        "workspace_id": WS_ID,
    });
    let target_edition_ref = add("edition", ArtifactKind::EditionV2, &target_edition);
    let target_edition_reference = json!({
        "api_version": "proof.dev/edition/v2",
        "edition_digest": target_edition_ref.digest.to_string(),
        "edition_id": EDITION_ID,
    });
    let delta = json!({
        "api_version": "proof.dev/edition-delta/v2",
        "base": {"edition": base_edition_reference, "state": base_state_reference},
        "objects": [
            {"after": object_a_state, "before": null, "object_id": CREATED_OBJECT_A_ID},
            {"after": object_b_state, "before": null, "object_id": CREATED_OBJECT_B_ID}
        ],
        "renditions": [
            {
                "after": rendition_a_state,
                "before": null,
                "locale": EN_LOCALE,
                "object_id": CREATED_OBJECT_A_ID,
            },
            {
                "after": rendition_b_state,
                "before": null,
                "locale": FR_CA_LOCALE,
                "object_id": CREATED_OBJECT_B_ID,
            }
        ],
        "schemas": [],
        "target": {"edition": target_edition_reference, "state": target_state_reference},
    });
    let delta_ref = add("edition_delta", ArtifactKind::ReleaseV2, &delta);
    let application_consequence = json!({
        "api_version": "proof.dev/application-consequence/v1",
        "operation_kind": "changeset.commit/v2",
        "result": {
            "application_consequence": "committed",
            "authoritative_sequence": TARGET_CONTENT_SEQUENCE,
            "base_state": base_state_reference,
            "changeset_id": CHANGES_ET_ID,
            "changeset_seal_digest": seal_ref.digest.to_string(),
            "exact_delta_digest": delta_ref.digest.to_string(),
            "resulting_state": target_state_reference,
            "validation_result_digest": validation_ref.digest.to_string(),
        },
    });
    let application_consequence_ref = add(
        "application_consequence",
        ArtifactKind::ReleaseV2,
        &application_consequence,
    );
    let submission = json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "changeset.submit/v2",
        "result": {
            "approval": null,
            "changeset_id": CHANGES_ET_ID,
            "occurred_at": CHANGESET_SUBMITTED_AT,
            "principal_id": H1_REQUESTER,
            "sealed_changeset_digest": seal_ref.digest.to_string(),
            "validation_results_digest": validation_ref.digest.to_string(),
        },
    });
    let _submission_ref = add("submission", ArtifactKind::OperationEffectV1, &submission);
    let approval = json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "changeset.approve/v2",
        "result": {
            "approval": "editorial",
            "changeset_id": CHANGES_ET_ID,
            "occurred_at": CHANGESET_APPROVED_AT,
            "principal_id": H2_APPROVER,
            "sealed_changeset_digest": seal_ref.digest.to_string(),
            "validation_results_digest": validation_ref.digest.to_string(),
        },
    });
    let approval_ref = add("approval", ArtifactKind::OperationEffectV1, &approval);
    let commit = json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "changeset.commit/v2",
        "result": {
            "application_consequence_digest": application_consequence_ref.digest.to_string(),
            "changeset_id": CHANGES_ET_ID,
            "committed_at": CHANGESET_COMMITTED_AT,
            "content_state_digest": target_state_ref.digest.to_string(),
            "principal_id": H2_APPROVER,
            "sealed_changeset_digest": seal_ref.digest.to_string(),
            "validation_results_digest": validation_ref.digest.to_string(),
        },
    });
    let commit_ref = add("commit", ArtifactKind::OperationEffectV1, &commit);
    let policy_decision = json!({
        "action": "release.create",
        "allowed": true,
        "api_version": "proof.dev/release-authorization-decision/v2",
        "base_release": base_release_reference,
        "changeset_id": CHANGES_ET_ID,
        "edition": target_edition_reference,
        "environment_config_digest": environment_digest.to_string(),
        "environment_config_version": 2,
        "environment_id": "preview",
        "evaluated_at": RELEASED_AT,
        "exact_delta_digest": delta_ref.digest.to_string(),
        "kind": "promotion",
        "operating_principal_id": H2_APPROVER,
        "policy_profile": "editorial-sod",
        "required_approval": "editorial",
        "resource_intent_id": RESOURCE_INTENT_ID,
        "rollback_target_release_id": null,
        "workspace_id": WS_ID,
    });
    let policy_decision_ref = add(
        "release_policy_decision",
        ArtifactKind::AuthorizationDecisionV1,
        &policy_decision,
    );
    let release = json!({
        "api_version": "proof.dev/release/v2",
        "authorization_decision_digest": policy_decision_ref.digest.to_string(),
        "base_release": base_release_reference,
        "changeset_id": CHANGES_ET_ID,
        "edition": target_edition_reference,
        "environment_config_digest": environment_digest.to_string(),
        "environment_config_version": 2,
        "environment_id": "preview",
        "exact_delta_digest": delta_ref.digest.to_string(),
        "key_id": release_key_id,
        "kind": "promotion",
        "principal_id": H2_APPROVER,
        "proof_id": PROOF_ID,
        "release_id": RELEASE_ID,
        "release_sequence": 2,
        "released_at": RELEASED_AT,
        "resource_intent_id": RESOURCE_INTENT_ID,
        "rollback_target_release_id": null,
        "workspace_id": WS_ID,
    });
    let release_ref = add("release_manifest", ArtifactKind::ReleaseV2, &release);
    let release_changeset_evidence = json!({
        "changeset_id": CHANGES_ET_ID,
        "effective_leaf_digest": effective_batch_ref.digest.to_string(),
        "proposal_digest": changeset_ref.digest.to_string(),
        "sealed_changeset_digest": seal_ref.digest.to_string(),
    });
    let content_evidence = json!({
        "base": base_closure,
        "changeset": release_changeset_evidence,
        "context_pack_digest": context_pack_ref.digest.to_string(),
        "renditions": [
            {
                "edit_id": PUT_A_EDIT_ID,
                "locale": EN_LOCALE,
                "object_id": CREATED_OBJECT_A_ID,
                "rendition_digest": rendition_a_ref.digest.to_string(),
                "schema_id": OBJECT_A_SCHEMA_ID,
                "schema_version": 1,
                "source_object_digest": create_a_ref.digest.to_string(),
            },
            {
                "edit_id": PUT_B_EDIT_ID,
                "locale": FR_CA_LOCALE,
                "object_id": CREATED_OBJECT_B_ID,
                "rendition_digest": rendition_b_ref.digest.to_string(),
                "schema_id": OBJECT_B_SCHEMA_ID,
                "schema_version": 1,
                "source_object_digest": create_b_ref.digest.to_string(),
            }
        ],
        "resource_intent": {
            "digest": resource_intent_ref.digest.to_string(),
            "intent_id": RESOURCE_INTENT_ID,
            "targets": targets,
        },
        "resulting_state": target_state_reference,
        "validations": [{
            "attempt": 1,
            "previous_validation_result_digest": null,
            "proposal_digest": changeset_ref.digest.to_string(),
            "results_digest": validation_ref.digest.to_string(),
            "valid": true,
        }],
    });
    let statement = json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicate": {
            "api_version": "proof.dev/release-proof-predicate/v2",
            "authority": {
                "authorization_decision_digest": policy_decision_ref.digest.to_string(),
                "human_principal_id": H2_APPROVER,
                "policy_profile": "editorial-sod",
            },
            "content_evidence": content_evidence,
            "exact_delta": delta,
            "exact_delta_digest": delta_ref.digest.to_string(),
            "implementation": {
                "canonical_json": "RFC 8785",
                "digest": "BLAKE3-256 domain-separated",
                "dsse": "DSSE v1 PAE",
                "known_state": "proof.dev/known-state/v2",
                "signature": "Ed25519",
                "statement": "in-toto Statement v1",
            },
            "release": {
                "base_release": base_release_reference,
                "changeset_id": CHANGES_ET_ID,
                "edition": target_edition_reference,
                "environment_id": "preview",
                "key_id": release_key_id,
                "kind": "promotion",
                "release_digest": release_ref.digest.to_string(),
                "release_id": RELEASE_ID,
                "release_sequence": 2,
                "released_at": RELEASED_AT,
                "resource_intent_id": RESOURCE_INTENT_ID,
                "rollback_target_release_id": null,
            },
            "state": target_state_reference,
            "workspace_id": WS_ID,
        },
        "predicateType": "urn:proof:attestation:release:v2",
        "subject": [
            {
                "digest": {"blake3": digest_hex(&target_edition_ref.digest)},
                "name": format!("proof:edition:{EDITION_ID}"),
            },
            {
                "digest": {"blake3": digest_hex(&release_ref.digest)},
                "name": format!("proof:release:{RELEASE_ID}"),
            }
        ],
    });
    let proof = dsse_envelope(release_key, release_key_id, &statement);
    let proof_ref = add(
        "release_proof_envelope",
        ArtifactKind::ProofEnvelopeV1,
        &proof,
    );
    let localized_result = json!({
        "proof_envelope_digest": proof_ref.digest.to_string(),
        "proof_id": PROOF_ID,
        "release_digest": release_ref.digest.to_string(),
        "release_id": RELEASE_ID,
        "release_manifest": release,
    });
    let _localized_result_ref = add(
        "localized_result",
        ArtifactKind::OperationEffectV1,
        &localized_result,
    );
    assert_ne!(approval_ref.digest, commit_ref.digest);

    let mut route_create_a = create_a_edit.clone();
    route_create_a.as_object_mut().unwrap().remove("edit_id");
    let mut route_put_a = put_a_edit.clone();
    route_put_a.as_object_mut().unwrap().remove("edit_id");
    let mut route_put_a_fr = route_put_a.clone();
    route_put_a_fr["locale"] = json!(FR_CA_LOCALE);
    route_put_a_fr["content"]["title"] = json!("Article publie");
    let mut route_create_b = create_b_edit.clone();
    route_create_b.as_object_mut().unwrap().remove("edit_id");
    let mut route_put_b = put_b_edit.clone();
    route_put_b.as_object_mut().unwrap().remove("edit_id");
    let mut route_put_b_en = route_put_b.clone();
    route_put_b_en["locale"] = json!(EN_LOCALE);
    route_put_b_en["content"] = json!({
        "legal": "Standard terms apply",
        "name": "Published product",
    });
    route_put_b["content"]["legal"] = json!(FORBIDDEN_LEGAL_CLAIM);
    let expected_add_input = json!({
        "api_version": "proof.dev/operation/changeset.add/v2",
        "changeset_id": CHANGES_ET_ID,
        "edits": [
            route_create_a,
            route_create_b,
            route_put_a,
            route_put_a_fr,
            route_put_b_en,
            route_put_b,
        ],
        "idempotency_key": INITIAL_ADD_APPLICATION_KEY,
    });
    CreationFixture {
        artifacts,
        resource_intent,
        context_pack,
        expected_add_input,
    }
}

fn seed_sidecar(db: &TestDb, fact_id: &str, fact_kind: &str, context: &str, body: &Value) {
    let bytes = canonical_bytes(body);
    db.seed_fact(
        fact_id,
        fact_kind,
        &derive_key_digest(context, &bytes),
        &bytes,
        0,
    );
}

fn seed_native_baseline(db: &TestDb, fixture: &CreationFixture) {
    let artifact_value = |kind: ArtifactKind, identity: &str, value: &str| {
        fixture
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == kind)
            .find_map(|artifact| {
                let parsed: Value = serde_json::from_slice(&artifact.bytes).ok()?;
                (parsed.get(identity).and_then(Value::as_str) == Some(value))
                    .then_some((artifact, parsed))
            })
            .expect("baseline artifact exists")
    };
    let (base_state_artifact, base_state) = fixture
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::KnownStateV2)
        .find_map(|artifact| {
            let parsed: Value = serde_json::from_slice(&artifact.bytes).ok()?;
            (parsed.get("authoritative_sequence").and_then(Value::as_u64)
                == Some(BASE_CONTENT_SEQUENCE))
            .then_some((artifact, parsed))
        })
        .expect("baseline Known State exists");
    let (base_edition_artifact, base_edition) =
        artifact_value(ArtifactKind::EditionV2, "edition_id", BASE_EDITION_ID);

    let workspace_metadata = json!({
        "api_version": "proof.dev/parity/workspace-metadata/v1",
        "principal_id": H1_REQUESTER,
        "storage_schema_version": 15,
        "workspace_id": WS_ID,
    });
    seed_sidecar(
        db,
        "workspace/metadata",
        "workspace_metadata",
        "proof:parity:workspace-metadata:v1",
        &workspace_metadata,
    );

    for (sequence, schema_id) in [(1_i64, OBJECT_A_SCHEMA_ID), (2_i64, OBJECT_B_SCHEMA_ID)] {
        let resource = fixture.context_pack["resources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|resource| resource["schema_candidates"][0]["schema_id"] == schema_id)
            .expect("one Context resource carries each baseline Schema");
        let candidate = &resource["schema_candidates"][0];
        let document = &candidate["document"];
        let bytes = canonical_bytes(document);
        let document_digest = artifact_digest(ArtifactKind::SchemaVersionV1, &bytes);
        db.seed_fact(
            &format!("schema/{schema_id}/1"),
            "schema",
            &document_digest,
            &bytes,
            sequence,
        );
        let sidecar = json!({
            "api_version": "proof.dev/parity/localizable-schema/v1",
            "authoritative_sequence": sequence,
            "changeset_id": "019f0000-0000-7000-8000-000000000001",
            "document": document,
            "document_digest": document_digest.to_string(),
            "edit_id": format!("019f0000-0000-7000-8000-00000000000{sequence}"),
            "schema_id": schema_id,
            "schema_version": 1,
        });
        seed_sidecar(
            db,
            &format!("localizable_schema/{schema_id}/1"),
            "localizable_schema",
            "proof:parity:localizable-schema:v1",
            &sidecar,
        );
    }

    let known_state_head = json!({
        "api_version": "proof.dev/parity/known-state-head/v1",
        "authoritative_sequence": BASE_CONTENT_SEQUENCE,
        "known_state_api_version": "proof.dev/known-state/v2",
        "state_digest": base_state_artifact.digest.to_string(),
    });
    seed_sidecar(
        db,
        "known_state/head",
        "known_state_head",
        "proof:parity:known-state-head:v1",
        &known_state_head,
    );
    let known_state_artifact = json!({
        "api_version": "proof.dev/parity/known-state-artifact/v1",
        "artifact_api_version": "proof.dev/known-state/v2",
        "authoritative_sequence": BASE_CONTENT_SEQUENCE,
        "manifest": base_state,
        "state_digest": base_state_artifact.digest.to_string(),
    });
    seed_sidecar(
        db,
        &format!("known_state_artifact/{BASE_CONTENT_SEQUENCE:020}"),
        "known_state_artifact",
        "proof:parity:known-state-artifact:v1",
        &known_state_artifact,
    );

    let environment_value = json!({
        "api_version": "proof.dev/environment-config-projection/v2",
        "environment_id": "preview",
        "version": 2,
        "workspace_id": WS_ID,
    });
    let environment_bytes = canonical_bytes(&environment_value);
    let environment_digest = domain_digest("proof:environment-config:v2", &environment_bytes);
    let environment = json!({
        "api_version": "proof.dev/parity/environment/v1",
        "config_digest": environment_digest.to_string(),
        "config_version": 2,
        "created_at": "2026-08-26T11:00:00Z",
        "delivery": {
            "destination_configuration_digest": fixed_digest(0x44).to_string(),
            "destination_configuration_version": 1,
        },
        "policy_profile": "editorial-sod",
        "principal_id": H1_REQUESTER,
        "required_approval": "editorial",
        "target_kind": "preview",
    });
    seed_sidecar(
        db,
        "environment/preview",
        "environment",
        "proof:parity:environment:v1",
        &environment,
    );

    let baseline_release = json!({
        "api_version": "proof.dev/release/v2",
        "authorization_decision_digest": fixed_digest(0x71).to_string(),
        "base_release": null,
        "changeset_id": null,
        "edition": {
            "api_version": "proof.dev/edition/v2",
            "digest": base_edition_artifact.digest.to_string(),
            "edition_id": BASE_EDITION_ID,
        },
        "environment_config_digest": environment_digest.to_string(),
        "environment_config_version": 2,
        "environment_id": "preview",
        "exact_delta_digest": fixed_digest(0x72).to_string(),
        "key_id": Ed25519SigningProvider::from_secret_bytes(&[0x22_u8; 32])
            .metadata().unwrap().key_id,
        "kind": "promotion",
        "principal_id": H1_REQUESTER,
        "proof_id": BASE_PROOF_ID,
        "release_id": BASE_RELEASE_ID,
        "release_sequence": 1,
        "released_at": "2026-08-26T11:01:00Z",
        "resource_intent_id": null,
        "rollback_target_release_id": null,
        "workspace_id": WS_ID,
    });
    let baseline_release_bytes = canonical_bytes(&baseline_release);
    let baseline_release_digest = artifact_digest(ArtifactKind::ReleaseV2, &baseline_release_bytes);
    db.seed_fact(
        &format!("release/{BASE_RELEASE_ID}"),
        "release_v2",
        &baseline_release_digest,
        &baseline_release_bytes,
        1,
    );
    let localized_edition = json!({
        "api_version": "proof.dev/parity/localized-edition/v1",
        "authoritative_sequence": BASE_CONTENT_SEQUENCE,
        "created_at": base_edition["created_at"],
        "edition_digest": base_edition_artifact.digest.to_string(),
        "edition_id": BASE_EDITION_ID,
        "state_api_version": "proof.dev/known-state/v2",
        "state_digest": base_state_artifact.digest.to_string(),
    });
    seed_sidecar(
        db,
        &format!("localized_edition/{BASE_EDITION_ID}"),
        "localized_edition",
        "proof:parity:localized-edition:v1",
        &localized_edition,
    );
    let edition_meta = json!({
        "api_version": "proof.dev/parity/edition-metadata/v1",
        "authoritative_sequence": BASE_CONTENT_SEQUENCE,
        "edition_api_version": "proof.dev/edition/v2",
        "edition_digest": base_edition_artifact.digest.to_string(),
        "edition_id": BASE_EDITION_ID,
        "state_digest": base_state_artifact.digest.to_string(),
    });
    seed_sidecar(
        db,
        &format!("edition_meta/{BASE_EDITION_ID}"),
        "edition_meta",
        "proof:parity:edition-metadata:v1",
        &edition_meta,
    );
    let release_meta = json!({
        "api_version": "proof.dev/parity/release-metadata/v1",
        "edition_digest": base_edition_artifact.digest.to_string(),
        "edition_id": BASE_EDITION_ID,
        "release_api_version": "proof.dev/release/v2",
        "release_digest": baseline_release_digest.to_string(),
        "release_id": BASE_RELEASE_ID,
        "released_at": "2026-08-26T11:01:00Z",
    });
    seed_sidecar(
        db,
        &format!("release_meta/{BASE_RELEASE_ID}"),
        "release_meta",
        "proof:parity:release-metadata:v1",
        &release_meta,
    );
    let environment_current = json!({
        "api_version": "proof.dev/parity/environment-current/v1",
        "environment_id": "preview",
        "release_id": BASE_RELEASE_ID,
        "release_sequence": 1,
    });
    seed_sidecar(
        db,
        "environment_current/preview",
        "environment_current",
        "proof:parity:environment-current:v1",
        &environment_current,
    );

    db.cleanup
        .lock()
        .unwrap()
        .client_mut()
        .execute(
            "UPDATE workspace_write_head
             SET content_sequence = $1, content_head_digest = $2,
                 release_sequence = 1, release_head_digest = $3
             WHERE singleton = 1",
            &[
                &i64::try_from(BASE_CONTENT_SEQUENCE).unwrap(),
                &base_state_artifact.digest.to_string(),
                &baseline_release_digest.to_string(),
            ],
        )
        .unwrap();
}

// ---------------------------------------------------------------------------
// The retained remote attempt derived from committed live records. This is the
// P-0013 producer-storage boundary, not a semantic lifecycle seeding path.
// ---------------------------------------------------------------------------

#[allow(clippy::type_complexity)]
struct AttemptFixture {
    release_v2_digest: ContentDigest,
    release_v2_bytes: Vec<u8>,
    nested: Vec<(String, ContentDigest)>,
    nested_bodies: Vec<(String, ContentDigest, Vec<u8>)>,
    closure_digest: ContentDigest,
    record_set_digest: ContentDigest,
    actor_evidence_digest: ContentDigest,
    authentication_event_digest: ContentDigest,
    command_input_digest: ContentDigest,
    command_envelope_digest: ContentDigest,
    target_decision_digest: ContentDigest,
    target_consequence_digest: ContentDigest,
    result_digest: ContentDigest,
    release_policy_decision_digest: ContentDigest,
    authority_policy_bundle_digest: ContentDigest,
    initial_authority_head: AuthorityHeadV1,
    presentation_id: String,
    authority_key_id: String,
    authority_public_b64: String,
    release_key_id: String,
    release_public_b64: String,
}

fn operation(name: &str, version: &str) -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: name.to_owned(),
        version: version.to_owned(),
    }
}

fn build_creation_inputs() -> CreationFixture {
    let release_provider = Ed25519SigningProvider::from_secret_bytes(&[0x22_u8; 32]);
    let release_metadata = release_provider.metadata().unwrap();
    let environment = canonical_bytes(&json!({
        "api_version": "proof.dev/environment-config-projection/v2",
        "workspace_id": WS_ID,
        "environment_id": "preview",
        "version": 2,
    }));
    build_creation_fixture(
        &SigningKey::from_bytes(&[0x22_u8; 32]),
        &release_metadata.key_id,
        domain_digest("proof:environment-config:v2", &environment),
    )
}

#[derive(Clone)]
struct RetainedArtifact {
    role: &'static str,
    kind: String,
    digest: ContentDigest,
    bytes: Vec<u8>,
}

struct AuthorityRow {
    sequence: u64,
    digest: ContentDigest,
    predecessor: ContentDigest,
    parsed: proof_remote::ParsedRemoteAuthorityRecordEnvelope,
}

fn retained_artifact(role: &'static str, kind: ArtifactKind, bytes: Vec<u8>) -> RetainedArtifact {
    RetainedArtifact {
        role,
        kind: kind.wire_name().to_owned(),
        digest: artifact_digest(kind, &bytes),
        bytes,
    }
}

fn retained_value(role: &'static str, kind: ArtifactKind, value: &Value) -> RetainedArtifact {
    retained_artifact(role, kind, canonical_bytes(value))
}

fn retained_environment(value: &Value) -> RetainedArtifact {
    let bytes = canonical_bytes(value);
    RetainedArtifact {
        role: "environment_config",
        kind: "environment_config_v2_projection".to_owned(),
        digest: domain_digest("proof:environment-config:v2", &bytes),
        bytes,
    }
}

#[allow(clippy::too_many_lines)]
fn materialize_live_attempt(db: &TestDb, creation: &CreationFixture) -> AttemptFixture {
    let authority_provider = Ed25519SigningProvider::from_secret_bytes(&[0x11_u8; 32]);
    let authority_metadata = authority_provider.metadata().unwrap();
    let release_provider = Ed25519SigningProvider::from_secret_bytes(&[0x22_u8; 32]);
    let release_metadata = release_provider.metadata().unwrap();

    let mut artifacts = Vec::<RetainedArtifact>::new();
    for schema_id in [OBJECT_A_SCHEMA_ID, OBJECT_B_SCHEMA_ID] {
        artifacts.push(retained_artifact(
            "schema",
            ArtifactKind::SchemaVersionV1,
            db.read_fact_bytes(&format!("schema/{schema_id}/1")),
        ));
    }

    let base_state_record =
        db.read_fact_value(&format!("known_state_artifact/{BASE_CONTENT_SEQUENCE:020}"));
    let base_state = base_state_record["manifest"].clone();
    artifacts.push(retained_value(
        "known_state",
        ArtifactKind::KnownStateV2,
        &base_state,
    ));
    let base_object_set = json!({
        "api_version": "proof.dev/object-set/v2",
        "objects": base_state["objects"],
        "renditions": base_state["renditions"],
    });
    artifacts.push(retained_value(
        "object_set",
        ArtifactKind::ObjectSetV2,
        &base_object_set,
    ));
    let base_edition = creation
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.kind == ArtifactKind::EditionV2
                && serde_json::from_slice::<Value>(&artifact.bytes).unwrap()["edition_id"]
                    == BASE_EDITION_ID
        })
        .expect("the allowed baseline includes its Edition");
    artifacts.push(retained_artifact(
        "edition",
        ArtifactKind::EditionV2,
        base_edition.bytes.clone(),
    ));
    artifacts.push(retained_artifact(
        "release_manifest",
        ArtifactKind::ReleaseV2,
        db.read_fact_bytes(&format!("release/{BASE_RELEASE_ID}")),
    ));

    artifacts.push(retained_artifact(
        "resource_intent",
        ArtifactKind::ContentResourceIntentV1,
        db.read_fact_bytes(&format!("resource_intent/{RESOURCE_INTENT_ID}")),
    ));
    let context_pack_bytes = db.read_fact_bytes(&format!("context_pack/{CONTEXT_PACK_ID}"));
    let context_pack: Value = serde_json::from_slice(&context_pack_bytes).unwrap();
    artifacts.push(retained_artifact(
        "context_pack",
        ArtifactKind::ContextPackV2,
        context_pack_bytes,
    ));
    let context_policy = context_pack["policy"].clone();
    let context_policy_artifact = retained_value(
        "context_policy_bundle",
        ArtifactKind::PolicyBundleV1,
        &context_policy,
    );
    assert_eq!(
        context_policy_artifact.digest.to_string(),
        context_pack["policy_digest"]
    );
    artifacts.push(context_policy_artifact);

    let edit_bytes = db.read_fact_rows(
        "localized_edit",
        &format!("localized_edit/{CHANGES_ET_ID}/%"),
    );
    let edits = edit_bytes
        .iter()
        .map(|bytes| serde_json::from_slice::<Value>(bytes).unwrap())
        .collect::<Vec<_>>();
    for (value, bytes) in edits.iter().zip(&edit_bytes) {
        let kind = match value["kind"].as_str().unwrap() {
            "object.create" => ArtifactKind::ObjectCreateEditV2,
            "object.locale.put" => ArtifactKind::EditV2,
            other => panic!("unexpected live Edit kind {other}"),
        };
        artifacts.push(retained_artifact("edit", kind, bytes.clone()));
    }

    let superseded_edit_ids = edits
        .iter()
        .filter_map(|edit| edit["supersedes_edit_id"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    let mut effective_edits = edits
        .iter()
        .filter(|edit| {
            !superseded_edit_ids.contains(edit["edit_id"].as_str().expect("live Edit identity"))
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(edits.len(), 7);
    assert_eq!(effective_edits.len(), 6);
    effective_edits.sort_by(|left, right| {
        let key = |value: &Value| {
            (
                u8::from(value["kind"] != "object.create"),
                value["object_id"].as_str().unwrap_or_default().to_owned(),
                value["locale"].as_str().unwrap_or_default().to_owned(),
            )
        };
        key(left).cmp(&key(right))
    });
    let effective_batch = json!({
        "api_version": "proof.dev/edit-batch/v2",
        "edits": effective_edits,
    });
    let effective_batch_artifact =
        retained_value("edit", ArtifactKind::EditBatchV2, &effective_batch);
    artifacts.push(effective_batch_artifact.clone());

    let changeset_record = db.read_fact_value(&format!("localized_changeset/{CHANGES_ET_ID}"));
    let effective_leaves = effective_edits
        .iter()
        .map(|edit| {
            let kind = if edit["kind"] == "object.create" {
                ArtifactKind::ObjectCreateEditV2
            } else {
                ArtifactKind::EditV2
            };
            let mut leaf = serde_json::Map::new();
            leaf.insert(
                "edit_digest".to_owned(),
                json!(artifact_digest(kind, &canonical_bytes(edit)).to_string()),
            );
            leaf.insert("edit_id".to_owned(), edit["edit_id"].clone());
            if let Some(locale) = edit.get("locale") {
                leaf.insert("locale".to_owned(), locale.clone());
            }
            leaf.insert("object_id".to_owned(), edit["object_id"].clone());
            Value::Object(leaf)
        })
        .collect::<Vec<_>>();
    let changeset = json!({
        "api_version": "proof.dev/changeset/v2",
        "base_state": {
            "api_version": changeset_record["base_state_api_version"],
            "authoritative_sequence": changeset_record["base_authoritative_sequence"],
            "digest": changeset_record["base_state_digest"],
        },
        "changeset_id": changeset_record["changeset_id"],
        "context_pack_digest": changeset_record["context_pack_digest"],
        "context_pack_id": changeset_record["context_pack_id"],
        "created_at": changeset_record["created_at"],
        "edits": edits,
        "effective_leaf_digest": effective_batch_artifact.digest.to_string(),
        "effective_leaves": effective_leaves,
        "intent": changeset_record["intent"],
        "principal_id": changeset_record["principal_id"],
        "resource_intent_digest": changeset_record["resource_intent_digest"],
        "resource_intent_id": changeset_record["resource_intent_id"],
        "workspace_id": changeset_record["workspace_id"],
    });
    let changeset_artifact = retained_value("changeset", ArtifactKind::ChangeSetV2, &changeset);
    assert_eq!(
        changeset_artifact.digest.to_string(),
        changeset_record["proposal_digest"]
    );
    artifacts.push(changeset_artifact.clone());

    let validation_records = db
        .read_fact_rows(
            "localized_validation",
            &format!("localized_validation/{CHANGES_ET_ID}/%"),
        )
        .into_iter()
        .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(validation_records.len(), 2);
    let mut validation_artifacts = Vec::new();
    for validation_record in &validation_records {
        let validation_artifact = retained_value(
            "validation_attempt",
            ArtifactKind::ValidationResultsV2,
            &validation_record["results"],
        );
        assert_eq!(
            validation_artifact.digest.to_string(),
            validation_record["results_digest"]
        );
        artifacts.push(validation_artifact.clone());
        validation_artifacts.push(validation_artifact);
    }
    let validation_record = validation_records.last().unwrap();
    let validation_artifact = validation_artifacts.last().unwrap();
    assert_eq!(validation_record["attempt"], 2);
    assert_eq!(validation_record["valid"], true);
    let seal = json!({
        "api_version": "proof.dev/changeset-seal/v2",
        "proposal_digest": changeset_artifact.digest.to_string(),
        "validation_results_digest": validation_artifact.digest.to_string(),
    });
    let seal_artifact = retained_value("changeset", ArtifactKind::ChangeSetV2, &seal);
    assert_eq!(
        seal_artifact.digest.to_string(),
        validation_record["sealed_changeset_digest"]
    );
    artifacts.push(seal_artifact.clone());

    for (role, fact_id, operation_kind, occurred_field) in [
        (
            "submission",
            format!("localized_submission/{CHANGES_ET_ID}"),
            "changeset.submit/v2",
            "submitted_at",
        ),
        (
            "approval",
            format!("localized_approval/{CHANGES_ET_ID}"),
            "changeset.approve/v2",
            "approved_at",
        ),
    ] {
        let fact = db.read_fact_value(&fact_id);
        let effect = json!({
            "api_version": "proof.dev/operation-effect/v1",
            "operation_kind": operation_kind,
            "result": {
                "approval": if role == "approval" { fact.get("approval_name").cloned().unwrap_or(Value::Null) } else { Value::Null },
                "changeset_id": fact["changeset_id"],
                "occurred_at": fact[occurred_field],
                "principal_id": fact["principal_id"],
                "sealed_changeset_digest": fact["sealed_changeset_digest"],
                "validation_results_digest": fact["validation_results_digest"],
            },
        });
        let artifact = retained_value(role, ArtifactKind::OperationEffectV1, &effect);
        assert_eq!(artifact.digest.to_string(), fact["effect_digest"]);
        artifacts.push(artifact);
    }

    for bytes in db.read_fact_rows("rendition", "rendition/%") {
        artifacts.push(retained_artifact(
            "locale_revision",
            ArtifactKind::ObjectLocaleRevisionV1,
            bytes,
        ));
    }
    let target_state_record = db.read_fact_value(&format!(
        "known_state_artifact/{TARGET_CONTENT_SEQUENCE:020}"
    ));
    let target_state = target_state_record["manifest"].clone();
    let target_state_artifact =
        retained_value("known_state", ArtifactKind::KnownStateV2, &target_state);
    assert_eq!(
        target_state_artifact.digest.to_string(),
        target_state_record["state_digest"]
    );
    artifacts.push(target_state_artifact);
    let target_object_set = json!({
        "api_version": "proof.dev/object-set/v2",
        "objects": target_state["objects"],
        "renditions": target_state["renditions"],
    });
    artifacts.push(retained_value(
        "object_set",
        ArtifactKind::ObjectSetV2,
        &target_object_set,
    ));

    let edition_record = db.read_fact_value(&format!("localized_edition/{EDITION_ID}"));
    let edition = edition_record["manifest"].clone();
    let edition_artifact = retained_value("edition", ArtifactKind::EditionV2, &edition);
    assert_eq!(
        edition_artifact.digest.to_string(),
        edition_record["edition_digest"]
    );
    artifacts.push(edition_artifact);

    let release_metadata_record = db.read_fact_value(&format!("release_metadata/{RELEASE_ID}"));
    let exact_delta = release_metadata_record["exact_delta"].clone();
    let delta_artifact = retained_value("edition_delta", ArtifactKind::ReleaseV2, &exact_delta);
    assert_eq!(
        delta_artifact.digest.to_string(),
        release_metadata_record["exact_delta_digest"]
    );
    artifacts.push(delta_artifact);

    let environment_record = db.read_fact_value("environment/preview");
    let environment = json!({
        "api_version": "proof.dev/environment-config-projection/v2",
        "workspace_id": WS_ID,
        "environment_id": "preview",
        "version": environment_record["config_version"],
    });
    let environment_artifact = retained_environment(&environment);
    assert_eq!(
        environment_artifact.digest.to_string(),
        environment_record["config_digest"]
    );
    artifacts.push(environment_artifact.clone());

    let release_bytes = db.read_fact_bytes(&format!("release/{RELEASE_ID}"));
    let release: Value = serde_json::from_slice(&release_bytes).unwrap();
    let release_artifact = retained_artifact(
        "release_manifest",
        ArtifactKind::ReleaseV2,
        release_bytes.clone(),
    );
    let policy_decision = json!({
        "action": "release.create",
        "allowed": true,
        "api_version": "proof.dev/release-authorization-decision/v2",
        "base_release": release["base_release"],
        "changeset_id": release["changeset_id"],
        "edition": release["edition"],
        "environment_config_digest": release["environment_config_digest"],
        "environment_config_version": release["environment_config_version"],
        "environment_id": release["environment_id"],
        "evaluated_at": release["released_at"],
        "exact_delta_digest": release["exact_delta_digest"],
        "kind": release["kind"],
        "operating_principal_id": release["principal_id"],
        "policy_profile": environment_record["policy_profile"],
        "required_approval": environment_record["required_approval"],
        "resource_intent_id": release["resource_intent_id"],
        "rollback_target_release_id": release["rollback_target_release_id"],
        "workspace_id": release["workspace_id"],
    });
    let policy_decision_artifact = retained_value(
        "release_policy_decision",
        ArtifactKind::AuthorizationDecisionV1,
        &policy_decision,
    );
    assert_eq!(
        policy_decision_artifact.digest.to_string(),
        release["authorization_decision_digest"]
    );
    artifacts.push(policy_decision_artifact.clone());
    artifacts.push(release_artifact.clone());

    let proof_record = db.read_fact_value(&format!("release_proof/{PROOF_ID}"));
    let proof_bytes = proof_record["envelope_json"]
        .as_str()
        .expect("live Proof envelope JSON")
        .as_bytes()
        .to_vec();
    let proof_artifact = retained_artifact(
        "release_proof_envelope",
        ArtifactKind::ProofEnvelopeV1,
        proof_bytes,
    );
    assert_eq!(
        proof_artifact.digest.to_string(),
        proof_record["envelope_digest"]
    );
    artifacts.push(proof_artifact.clone());

    let release_result = db
        .read_fact_rows("release_operation", "release_operation/%")
        .into_iter()
        .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap())
        .find(|value| value["release_id"] == RELEASE_ID)
        .expect("live Release operation result")["result"]
        .clone();
    artifacts.push(retained_value(
        "localized_result",
        ArtifactKind::OperationEffectV1,
        &release_result,
    ));

    let authority_rows = {
        let mut guard = db.cleanup.lock().unwrap();
        guard
            .client_mut()
            .query(
                "SELECT authority_sequence, record_digest, predecessor_digest, envelope
                 FROM remote_authority_records ORDER BY authority_sequence",
                &[],
            )
            .unwrap()
            .into_iter()
            .map(|row| {
                let envelope: Vec<u8> = row.get(3);
                AuthorityRow {
                    sequence: u64::try_from(row.get::<_, i64>(0)).unwrap(),
                    digest: row.get::<_, String>(1).parse().unwrap(),
                    predecessor: row.get::<_, String>(2).parse().unwrap(),
                    parsed: proof_remote::parse_remote_authority_record_envelope(&envelope)
                        .unwrap(),
                }
            })
            .collect::<Vec<_>>()
    };
    let binding_index = authority_rows
        .iter()
        .position(|row| {
            matches!(
                &row.parsed.record,
                RemoteAuthorityRecordV1::AgentBindingIssue(binding)
                    if binding.binding_id.to_string() == AGENT_BINDING_ID
            )
        })
        .expect("live signed Agent binding record");
    let consequence_index = authority_rows
        .iter()
        .position(|row| {
            matches!(
                &row.parsed.record,
                RemoteAuthorityRecordV1::RemoteApplicationConsequence(consequence)
                    if consequence.operation.name == "release.create"
                        && consequence.outcome == ApplicationConsequenceOutcome::Success
                        && consequence.application_key.as_deref() == Some(RELEASE_APPLICATION_KEY)
            )
        })
        .expect("live signed Release consequence");
    let target_consequence = match &authority_rows[consequence_index].parsed.record {
        RemoteAuthorityRecordV1::RemoteApplicationConsequence(consequence) => consequence.clone(),
        _ => unreachable!(),
    };
    let decision_index = authority_rows
        .iter()
        .position(|row| row.digest == target_consequence.decision_digest)
        .expect("live signed Release decision");
    let target_decision = match &authority_rows[decision_index].parsed.record {
        RemoteAuthorityRecordV1::RemoteAuthorizationDecision(decision) => decision.clone(),
        _ => panic!("Release consequence does not bind an authorization decision"),
    };
    assert!(binding_index < decision_index && decision_index < consequence_index);
    assert_eq!(
        target_consequence.application_effect_digest,
        Some(release_artifact.digest)
    );
    assert_eq!(
        target_consequence.result_digest,
        Some(proof_remote::registry::operation_effect_digest(&release_result).unwrap())
    );

    let suffix_rows = &authority_rows[binding_index..=consequence_index];
    for pair in suffix_rows.windows(2) {
        assert_eq!(pair[1].sequence, pair[0].sequence + 1);
        assert_eq!(pair[1].predecessor, pair[0].digest);
    }
    let initial_authority_head = AuthorityHeadV1 {
        sequence: suffix_rows[0].sequence - 1,
        record_digest: suffix_rows[0].predecessor,
    };
    let included_head = AuthorityHeadV1 {
        sequence: suffix_rows.last().unwrap().sequence,
        record_digest: suffix_rows.last().unwrap().digest,
    };
    let record_set = RemoteAuthorityRecordSetV1 {
        api_version: RemoteAuthorityRecordSetApiVersion::Tag,
        workspace_id: WS_ID.to_owned(),
        base_head: initial_authority_head,
        record_order: "decoded authority_sequence ascending and contiguous".to_owned(),
        records: suffix_rows
            .iter()
            .map(|row| row.parsed.envelope.clone())
            .collect(),
        included_head,
    };
    let record_set_bytes = canonical_bytes(&serde_json::to_value(&record_set).unwrap());
    let record_set_digest = domain_digest(
        REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT,
        &record_set_bytes,
    );

    let agent_authorization = target_decision
        .agent_authorization
        .as_ref()
        .expect("Release decision carries Agent authorization");
    let presentation_consumptions: i64 = {
        let mut guard = db.cleanup.lock().unwrap();
        guard
            .client_mut()
            .query_one(
                "SELECT COUNT(*) FROM facts WHERE fact_id = $1",
                &[&format!(
                    "presentation_consumption/{}",
                    agent_authorization.presentation_id
                )],
            )
            .unwrap()
            .get(0)
    };
    assert_eq!(presentation_consumptions, 1);
    let (actor_evidence_digest, actor_evidence_bytes) = {
        let mut guard = db.cleanup.lock().unwrap();
        guard
            .client_mut()
            .query(
                "SELECT digest, body FROM artifact_body_pg
                 WHERE kind = 'remote-actor-evidence' ORDER BY committed_at",
                &[],
            )
            .unwrap()
            .into_iter()
            .find_map(|row| {
                let bytes: Vec<u8> = row.get(1);
                let value: Value = serde_json::from_slice(&bytes).ok()?;
                (value["presentation_id"] == agent_authorization.presentation_id
                    && value["operation"]["name"] == "release.create")
                    .then(|| (row.get::<_, String>(0).parse().unwrap(), bytes))
            })
            .expect("live Release actor evidence")
    };
    let actor_evidence: Value = serde_json::from_slice(&actor_evidence_bytes).unwrap();
    let authentication_event_digest = actor_evidence["authentication_event_digest"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let command_input_digest = agent_authorization.command_digest;
    let command_envelope_digest = agent_authorization.command_envelope_digest;
    let authentication_event_bytes =
        db.read_artifact_bytes("remote-authentication-event", authentication_event_digest);
    let command_input_bytes = db.read_artifact_bytes("remote-command-input", command_input_digest);
    let command_envelope_bytes = db.read_artifact_bytes(
        "remote-authenticated-command-envelope",
        command_envelope_digest,
    );
    assert_eq!(
        domain_digest(
            AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT,
            &actor_evidence_bytes
        ),
        actor_evidence_digest
    );
    assert_eq!(
        domain_digest(
            REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT,
            &authentication_event_bytes
        ),
        authentication_event_digest
    );
    assert_eq!(
        artifact_digest(ArtifactKind::CommandV1, &command_input_bytes),
        command_input_digest
    );
    assert_eq!(
        artifact_digest(
            ArtifactKind::AuthenticatedCommandEnvelopeV1,
            &command_envelope_bytes
        ),
        command_envelope_digest
    );

    let mut unique = BTreeMap::<(String, String), (ContentDigest, Vec<u8>)>::new();
    let mut role_bindings = Vec::new();
    for artifact in artifacts {
        let key = (artifact.kind.clone(), artifact.digest.to_string());
        if let Some((_, existing)) = unique.get(&key) {
            assert_eq!(existing, &artifact.bytes);
        } else {
            unique.insert(key, (artifact.digest, artifact.bytes));
        }
        role_bindings.push(AcceptedArtifactRoleBindingV1 {
            artifact: AcceptedArtifactRefV1 {
                artifact_kind: artifact.kind,
                digest: artifact.digest,
            },
            role: artifact.role.to_owned(),
        });
    }
    role_bindings.push(AcceptedArtifactRoleBindingV1 {
        artifact: AcceptedArtifactRefV1 {
            artifact_kind: "release_v2".to_owned(),
            digest: release_artifact.digest,
        },
        role: "application_effect".to_owned(),
    });
    role_bindings.sort_by(|left, right| {
        (
            left.role.as_str(),
            left.artifact.artifact_kind.as_str(),
            digest_hex(&left.artifact.digest),
        )
            .cmp(&(
                right.role.as_str(),
                right.artifact.artifact_kind.as_str(),
                digest_hex(&right.artifact.digest),
            ))
    });
    role_bindings.dedup_by(|left, right| left == right);

    let mut closure_artifacts = unique
        .iter()
        .map(
            |((kind, _), (digest_value, bytes))| AcceptedArtifactDescriptorV1 {
                artifact: AcceptedArtifactRefV1 {
                    artifact_kind: kind.clone(),
                    digest: *digest_value,
                },
                availability: AcceptedArtifactAvailabilityV1 {
                    state: "included".to_owned(),
                    byte_length: byte_len(bytes),
                },
            },
        )
        .collect::<Vec<_>>();
    closure_artifacts.sort_by(|left, right| {
        (
            left.artifact.artifact_kind.as_str(),
            digest_hex(&left.artifact.digest),
        )
            .cmp(&(
                right.artifact.artifact_kind.as_str(),
                digest_hex(&right.artifact.digest),
            ))
    });
    let closure = RemoteReleaseArtifactClosureV1 {
        api_version: RemoteReleaseArtifactClosureApiVersion::Tag,
        workspace_id: WS_ID.to_owned(),
        artifact_order: "artifact_kind, digest UTF-8 bytewise ascending".to_owned(),
        artifacts: closure_artifacts,
        role_binding_order: "role, artifact_kind, digest UTF-8 bytewise ascending".to_owned(),
        role_bindings,
        entrypoints: RemoteReleaseArtifactClosureEntrypointsV1 {
            target_release_manifest: AcceptedArtifactRefV1 {
                artifact_kind: "release_v2".to_owned(),
                digest: release_artifact.digest,
            },
            target_release_proof_envelope: AcceptedArtifactRefV1 {
                artifact_kind: "proof_envelope_v1".to_owned(),
                digest: proof_artifact.digest,
            },
            target_environment_config: AcceptedArtifactRefV1 {
                artifact_kind: "environment_config_v2_projection".to_owned(),
                digest: environment_artifact.digest,
            },
            application_effect: AcceptedArtifactRefV1 {
                artifact_kind: "release_v2".to_owned(),
                digest: release_artifact.digest,
            },
            result_derivation:
                "proof.dev/release-create-output/v2 from target ReleaseV2 plus target Release Proof envelope digest"
                    .to_owned(),
        },
    };
    let closure_bytes = canonical_bytes(&serde_json::to_value(&closure).unwrap());
    let closure_digest = domain_digest(
        REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT,
        &closure_bytes,
    );

    db.seed_artifact("release-artifact-closure", &closure_digest, &closure_bytes);
    db.seed_artifact("authority-fact", &record_set_digest, &record_set_bytes);
    for ((kind, _), (digest_value, bytes)) in &unique {
        db.seed_artifact(kind, digest_value, bytes);
    }
    let material = json!({
        "api_version": "proof.dev/release-export-material/v1",
        "workspace_id": WS_ID,
        "release_id": RELEASE_ID,
        "release_digest": release_artifact.digest.to_string(),
        "release_artifact_closure_digest": closure_digest.to_string(),
        "authority_record_set_digest": record_set_digest.to_string(),
        "actor_context_evidence_digest": actor_evidence_digest.to_string(),
        "authentication_event_digest": authentication_event_digest.to_string(),
        "command_input_digest": command_input_digest.to_string(),
        "authenticated_command_envelope_digest": command_envelope_digest.to_string(),
        "target_decision_digest": authority_rows[decision_index].digest.to_string(),
        "target_consequence_digest": authority_rows[consequence_index].digest.to_string(),
        "result_digest": target_consequence.result_digest.unwrap().to_string(),
        "release_policy_decision_digest": policy_decision_artifact.digest.to_string(),
    });
    let material_bytes = canonical_bytes(&material);
    db.seed_fact(
        &format!("release_export_material/{RELEASE_ID}"),
        "release_export_material",
        &domain_digest("proof:release-export-material:v1", &material_bytes),
        &material_bytes,
        i64::try_from(included_head.sequence).unwrap(),
    );

    let nested_bodies = unique
        .into_iter()
        .map(|((kind, _), (digest_value, bytes))| (kind, digest_value, bytes))
        .collect::<Vec<_>>();
    let nested = nested_bodies
        .iter()
        .map(|(kind, digest_value, _)| (kind.clone(), *digest_value))
        .collect();
    AttemptFixture {
        release_v2_digest: release_artifact.digest,
        release_v2_bytes: release_bytes,
        nested,
        nested_bodies,
        closure_digest,
        record_set_digest,
        actor_evidence_digest,
        authentication_event_digest,
        command_input_digest,
        command_envelope_digest,
        target_decision_digest: authority_rows[decision_index].digest,
        target_consequence_digest: authority_rows[consequence_index].digest,
        result_digest: target_consequence.result_digest.unwrap(),
        release_policy_decision_digest: policy_decision_artifact.digest,
        authority_policy_bundle_digest: agent_authorization.policy_bundle_digest,
        initial_authority_head,
        presentation_id: agent_authorization.presentation_id.clone(),
        authority_key_id: authority_metadata.key_id,
        authority_public_b64: BASE64.encode(authority_metadata.public_key),
        release_key_id: release_metadata.key_id,
        release_public_b64: BASE64.encode(release_metadata.public_key),
    }
}

// ---------------------------------------------------------------------------
// In-process HTTP harness.
// ---------------------------------------------------------------------------

fn query_param(url: &str, key: &str) -> String {
    let query = url.split_once('?').map_or("", |(_, q)| q);
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return v.to_owned();
        }
    }
    panic!("missing query parameter {key} in {url}");
}

fn set_cookie_value(resp: &axum::response::Response, name: &str) -> String {
    let values: Vec<_> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    for value in values {
        let pair = value.split(';').next().unwrap_or("");
        if let Some((k, v)) = pair.split_once('=')
            && k == name
        {
            return v.to_owned();
        }
    }
    panic!("missing set-cookie {name}");
}

async fn response_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("response body is readable");
    serde_json::from_slice(&bytes).expect("response body is JSON")
}

async fn response_bytes(resp: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("response body is readable")
        .to_vec()
}

struct HumanSession {
    cookie: String,
    csrf: String,
}

const PKCE_VERIFIER: &str = "deterministic-pkce-verifier-0000000000000000000000000000000000000000";

/// Acquires one live OIDC session through the deterministic-issuer BFF path:
/// login redirect, provider-issued one-use code, callback exchange, and the
/// `GET /api/v1/session` CSRF acquisition route.
async fn login_human(
    app: &axum::Router,
    issuer: &proof_server::issuer::DeterministicIssuer,
    subject: &str,
    expected_principal: &str,
) -> HumanSession {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/oidc/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let authorize_url = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("login carries a Location header")
        .to_owned();
    let state = query_param(&authorize_url, "state");
    let nonce = query_param(&authorize_url, "nonce");

    let redirect_uri = issuer.config().redirect_uri.clone();
    let code = issuer
        .issue_code(&redirect_uri, PKCE_VERIFIER, &nonce, subject)
        .expect("issuer mints the code")
        .code;
    let issuer_uri = issuer.issuer().to_owned();

    let callback_uri = format!("/auth/oidc/callback?code={code}&state={state}&iss={issuer_uri}");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(callback_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let session_id = set_cookie_value(&resp, "__Host-Http-Proof-Session");
    let cookie = format!("__Host-Http-Proof-Session={session_id}");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header(header::COOKIE, cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let projection = response_json(resp).await;
    assert_eq!(projection["principal_id"], expected_principal);
    let csrf = projection["csrf_token"]
        .as_str()
        .expect("session projection carries a CSRF token")
        .to_owned();
    HumanSession { cookie, csrf }
}

fn operation_request_body(operation: &RemoteOperationV1, input: &Value) -> Value {
    json!({
        "api_version": "proof.dev/http-human-operation-request/v1",
        "workspace_id": WS_ID,
        "operation": operation,
        "input": input,
    })
}

async fn post_operation(
    app: &axum::Router,
    route_prefix: &str,
    name: &str,
    major: &str,
    session: Option<&HumanSession>,
    body: &Value,
) -> axum::response::Response {
    let uri = format!("/api/v1/{route_prefix}/operations/{name}/{major}");
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::HOST, "proof.example.test")
        .header(header::ORIGIN, "https://proof.example.test");
    if let Some(session) = session {
        builder = builder
            .header("proof-csrf", session.csrf.clone())
            .header(header::COOKIE, session.cookie.clone());
    }
    app.clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Asserts one successful dispatch envelope and returns the whole envelope.
async fn expect_success(resp: axum::response::Response, label: &str) -> Value {
    let status = resp.status();
    let envelope = response_json(resp).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{label} must succeed over HTTP: {envelope}"
    );
    assert_eq!(
        envelope["api_version"],
        "proof.dev/http-operation-result/v1"
    );
    assert!(envelope["committed_anchor"].is_object());
    envelope
}

/// Asserts one RFC 9457 Problem rejection with the exact frozen Problem code.
async fn expect_problem(resp: axum::response::Response, expected_code: &str, label: &str) -> Value {
    let status = resp.status();
    let problem = response_json(resp).await;
    assert_eq!(
        problem["code"], expected_code,
        "{label} must fail with {expected_code}"
    );
    assert_eq!(
        u16::try_from(problem["status"].as_u64().unwrap()).unwrap(),
        status.as_u16(),
        "{label} Problem status must match the HTTP status"
    );
    problem
}

// ---------------------------------------------------------------------------
// Dual-auth Agent invocation builder (fresh single-use presentation each call).
// ---------------------------------------------------------------------------

fn build_agent_invocation(
    agent_provider: &Ed25519SigningProvider,
    authority_operation: AuthorityOperation,
    normalized_input: Map<String, Value>,
) -> AuthenticatedInvocationV1 {
    let command_input = CommandInputV1 {
        api_version: CommandInputApiVersion::V1,
        workspace_id: WS_ID.parse().unwrap(),
        operation: authority_operation,
        requesting_principal_id: H1_REQUESTER.parse().unwrap(),
        operating_principal_id: G_OPERATOR.parse().unwrap(),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        idempotency_key: normalized_input
            .get("idempotency_key")
            .and_then(Value::as_str)
            .map(|key| key.parse().unwrap()),
        normalized_input,
    };
    let command_input_value = serde_json::to_value(&command_input).unwrap();
    let canonical_command = canonicalize(&command_input_value).unwrap();
    let command_digest = digest(ArtifactKind::CommandV1, &canonical_command);

    let payload = AuthenticatedCommandV1 {
        api_version: AuthenticatedCommandApiVersion::V1,
        audience: AuthorityAudience::for_workspace(WS_ID.parse().unwrap()),
        workspace_id: WS_ID.parse().unwrap(),
        operation: authority_operation,
        binding_id: AGENT_BINDING_ID.parse().unwrap(),
        requesting_principal_id: H1_REQUESTER.parse().unwrap(),
        operating_principal_id: G_OPERATOR.parse().unwrap(),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        command_digest,
        idempotency_key: command_input.idempotency_key,
        presentation_id: uuid::Uuid::now_v7().to_string().parse().unwrap(),
        issued_at: timestamp_offset(-10),
        expires_at: timestamp_offset(120),
    };
    let signed = sign_authority_payload(
        AuthorityPayloadProfile::AuthenticatedCommand,
        &payload,
        &[agent_provider],
    )
    .unwrap();
    AuthenticatedInvocationV1 {
        api_version: AuthenticatedInvocationApiVersion::V1,
        command_input,
        authentication: AuthenticatedCommandEnvelopeJson::new(signed.envelope_json).unwrap(),
    }
}

async fn run_agent_operation(
    app: &axum::Router,
    h1: &HumanSession,
    agent_provider: &Ed25519SigningProvider,
    authority_operation: AuthorityOperation,
    normalized_input: Map<String, Value>,
    label: &str,
) -> Value {
    let invocation = build_agent_invocation(agent_provider, authority_operation, normalized_input);
    let body = json!({
        "api_version": "proof.dev/http-agent-operation-request/v1",
        "correlation_id": HTTP_CORRELATION_ID,
        "operation": {
            "name": authority_operation.name(),
            "version": authority_operation.version()
        },
        "invocation": serde_json::to_value(&invocation).unwrap()
    });
    let resp = post_operation(
        app,
        "agent",
        authority_operation.name(),
        authority_operation.version().rsplit('/').next().unwrap(),
        Some(h1),
        &body,
    )
    .await;
    expect_success(resp, label).await
}

async fn run_agent_operation_problem(
    app: &axum::Router,
    h1: &HumanSession,
    agent_provider: &Ed25519SigningProvider,
    authority_operation: AuthorityOperation,
    normalized_input: Map<String, Value>,
    expected_code: &str,
    label: &str,
) -> Value {
    let invocation = build_agent_invocation(agent_provider, authority_operation, normalized_input);
    let body = json!({
        "api_version": "proof.dev/http-agent-operation-request/v1",
        "correlation_id": HTTP_CORRELATION_ID,
        "operation": {
            "name": authority_operation.name(),
            "version": authority_operation.version()
        },
        "invocation": serde_json::to_value(&invocation).unwrap()
    });
    let resp = post_operation(
        app,
        "agent",
        authority_operation.name(),
        authority_operation.version().rsplit('/').next().unwrap(),
        Some(h1),
        &body,
    )
    .await;
    expect_problem(resp, expected_code, label).await
}

fn input_object(value: &Value) -> Map<String, Value> {
    value.as_object().expect("input object").clone()
}

// ---------------------------------------------------------------------------
// Typed export-surface helpers (the HTTP envelope carries only the effect
// digest; the typed public entrypoints expose the exact result/status bytes).
// ---------------------------------------------------------------------------

fn h2_session_record() -> SessionRecord {
    SessionRecord {
        session_id_hash: [0_u8; 32],
        workspace_id: WS_ID.to_owned(),
        principal_id: H2_APPROVER.to_owned(),
        binding_id: H2_BINDING_ID.to_owned(),
        authentication_event_id: "019c0000-0000-7000-8000-0000000000c2".to_owned(),
        csrf_digest: [0_u8; 32],
        created_at: SystemTime::now(),
        last_seen: SystemTime::now(),
        absolute_expiry: SystemTime::now() + Duration::from_secs(3_600),
    }
}

fn h2_export_context(
    db: &TestDb,
    operation: &RemoteOperationV1,
    input: &Value,
) -> AuthenticatedActorContextV2 {
    let mut context =
        proof_server::authz::authenticate_human_session(&db.state, &h2_session_record())
            .expect("H2 export context authenticates");
    let normalized_input_digest =
        proof_remote::identity::normalized_operation_input_digest(input, operation).unwrap();
    if let AuthenticatedActorContextV2::Human(human) = &mut context {
        human.operation = operation.clone();
        human.normalized_input_digest = normalized_input_digest;
    }
    context
}

fn evidence_export_operation() -> RemoteOperationV1 {
    operation("evidence.export", "proof.dev/operation/evidence.export/v2")
}

fn evidence_export_get_operation() -> RemoteOperationV1 {
    operation(
        "evidence.export.get",
        "proof.dev/operation/evidence.export.get/v1",
    )
}

fn export_input(release_digest: &ContentDigest) -> Value {
    json!({
        "idempotency_key": EXPORT_APPLICATION_KEY,
        "release_id": RELEASE_ID,
        "release_digest": release_digest.to_string(),
    })
}

fn typed_export_create(db: &TestDb, input: &Value) -> EvidenceExportResultV2 {
    let op = evidence_export_operation();
    let context = h2_export_context(db, &op, input);
    let decision = proof_server::authz::evaluate_authorization(&db.state, &context, input)
        .expect("export create decision");
    evidence_export_v2(&db.state, &op, input, &context, &decision).expect("typed export create")
}

fn typed_export_status(db: &TestDb, export_id: &str) -> EvidenceExportStatusV1 {
    let op = evidence_export_get_operation();
    let input = json!({ "export_id": export_id });
    let context = h2_export_context(db, &op, &input);
    let decision = proof_server::authz::evaluate_authorization(&db.state, &context, &input)
        .expect("export get decision");
    evidence_export_get_v1(&db.state, &op, &input, &context, &decision)
        .expect("typed export status")
}

// ---------------------------------------------------------------------------
// Caller trust policy and verifier input (remote_impl.rs fixture style).
// ---------------------------------------------------------------------------

struct TrustInputs {
    input: proof_remote::RemoteVerifierInputV2,
}

fn trusted_key(key_id: &str, public_b64: &str) -> Value {
    json!({
        "key_id": key_id,
        "public_key": public_b64,
        "not_before": "2026-08-01T00:00:00Z",
        "not_after": null,
        "revoked_at": null,
    })
}

fn head_value(sequence: u64, digest_str: &str) -> Value {
    json!({ "sequence": sequence, "record_digest": digest_str })
}

fn build_trust_inputs(fixture: &AttemptFixture) -> TrustInputs {
    let issuer_configuration_digest = IdentityFixtureV1::deterministic()
        .issuer_configuration
        .digest()
        .unwrap();
    let policy_value = json!({
        "api_version": "proof.dev/verification-trust-policy/v2",
        "workspace_id": WS_ID,
        "registry_resolution": {
            "profile": "proof.verifier/collaboration-registry/v1",
            "source": "verifier-built-in-closed-hash-to-rfc8785-document-table",
            "unknown_hash_result": "Invalid",
            "hash_mismatch_result": "Invalid"
        },
        "authority": {
            "initial_root": trusted_key(&fixture.authority_key_id, &fixture.authority_public_b64),
            "initial_head": head_value(
                fixture.initial_authority_head.sequence,
                &fixture.initial_authority_head.record_digest.to_string()
            ),
            "accepted_authorization_registry_hashes": [REMOTE_AUTHORIZATION_PROJECTION_SHA256],
            "accepted_operation_registry_hashes": [COMPLETE_HTTP_OPERATION_REGISTRY_SHA256],
            "accepted_policy_bundles": [
                {
                    "policy_profile": "proof.local/authority/direct/v1",
                    "policy_bundle_digest": fixture.authority_policy_bundle_digest.to_string()
                }
            ],
            "checkpoint_requirement": "internal_prefix_only",
            "compromise_cutoff": null
        },
        "release": {
            "trusted_signers": [trusted_key(&fixture.release_key_id, &fixture.release_public_b64)],
            "accepted_predicate_types": ["urn:proof:attestation:release:v2"],
            "accepted_policy_profiles": [
                {"policy_profile": "proof.local/release-policy/v1", "environment_config_digest": ZERO_DIGEST_STR}
            ]
        },
        "remote_identity": {
            "accepted_oidc_issuer_configuration_digests": [issuer_configuration_digest.to_string()]
        },
        "disclosure": { "requesting_subject_opening": "optional" },
        "limits": {
            "max_verifier_input_bytes": 268_435_456,
            "max_manifest_bytes": 4_194_304,
            "max_artifacts": 4096,
            "max_authority_records": 512,
            "max_artifact_bytes": 4_194_304,
            "max_total_bytes": 268_435_456,
            "max_json_depth": 128
        }
    });
    let policy_canonical = canonical_bytes(&policy_value);
    let trust_policy_digest =
        domain_digest(VERIFICATION_TRUST_POLICY_DIGEST_CONTEXT, &policy_canonical);

    let input_json = json!({
        "type": "RemoteVerifierInputV2",
        "api_version": "proof.dev/remote-verifier-input/v2",
        "verification_trust_policy": policy_value,
        "trust_policy_digest": trust_policy_digest.to_string(),
        "subject_openings": [],
        "authority_checkpoint": null,
        "environment_release_checkpoint": null,
        "external_artifacts": [],
        "bundle_hints_are_authority": false,
        "network_access": false,
        "database_access": false,
        "session_access": false,
        "private_key_count": 0,
        "credential_count": 0
    });
    let input: proof_remote::RemoteVerifierInputV2 =
        serde_json::from_value(input_json).expect("verifier input builds");
    TrustInputs { input }
}

// ---------------------------------------------------------------------------
// Step 1: capabilities discovery is a public read.
// ---------------------------------------------------------------------------

async fn step_01_capabilities(app: &axum::Router) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let capabilities = response_json(resp).await;
    assert_eq!(capabilities["route_count"], 9);
    assert_eq!(capabilities["human_operation_count"], 26);
    assert_eq!(capabilities["agent_operation_count"], 14);
}

// ---------------------------------------------------------------------------
// Step 3: workspace init and role assignment through the live route.
// ---------------------------------------------------------------------------

async fn step_03_workspace_init_and_role_assignment(app: &axum::Router, h1: &HumanSession) {
    let op = human_operation(
        "workspace-role.assign",
        "proof.dev/operation/workspace-role.assign/v1",
    );
    let input = json!({
        "workspace_id": WS_ID,
        "principal_id": H2_APPROVER,
        "role": "content.publisher",
        "assignment_id": "019d0000-0000-7000-8000-0000000000aa",
        "idempotency_key": "019d0000-0000-7000-8000-0000000000ab",
    });
    let resp = post_operation(
        app,
        "human",
        op.name.as_str(),
        "v1",
        Some(h1),
        &operation_request_body(&op, &input),
    )
    .await;
    let envelope = expect_success(resp, "H1 assigns content.publisher to H2").await;
    assert_eq!(envelope["result"]["principal_id"], H2_APPROVER);
    assert_eq!(envelope["result"]["role"], "content.publisher");
}

// ---------------------------------------------------------------------------
// Step 4: Delegation H1->G and the ContextPack.
// ---------------------------------------------------------------------------

async fn step_04_delegation(app: &axum::Router, h1: &HumanSession, resource_intent_digest: &str) {
    let delegation_op = human_operation(
        "delegation.issue",
        "proof.dev/operation/delegation.issue/v2",
    );
    let not_before = timestamp_offset(1).to_string();
    let delegation_input = json!({
        "actions": [
            "changeset:add",
            "changeset:commit",
            "changeset:create",
            "changeset:diff",
            "changeset:get",
            "changeset:submit",
            "changeset:validate",
            "context:build",
            "edition:create",
            "object:query_released",
            "release:create",
        ],
        "constraints": {
            "allow_subdelegation": false,
            "max_context_bytes": 65536,
            "max_edits_per_changeset": 7,
            "max_objects": 2,
        },
        "delegation_id": DELEGATION_ID,
        "expires_at": CONTEXT_EXPIRES_AT,
        "idempotency_key": "019d0000-0000-7000-8000-0000000000b1",
        "not_before": not_before,
        "operating_principal_id": G_OPERATOR,
        "resource_intent_digest": resource_intent_digest,
        "resource_intent_id": RESOURCE_INTENT_ID,
        "scope": {
            "environment_ids": ["preview"],
            "locales": [EN_LOCALE, FR_CA_LOCALE],
            "object_ids": [CREATED_OBJECT_A_ID, CREATED_OBJECT_B_ID],
            "schema_ids": [OBJECT_A_SCHEMA_ID, OBJECT_B_SCHEMA_ID],
        },
    });
    let resp = post_operation(
        app,
        "human",
        delegation_op.name.as_str(),
        "v2",
        Some(h1),
        &operation_request_body(&delegation_op, &delegation_input),
    )
    .await;
    let envelope = expect_success(resp, "H1 issues Delegation H1->G").await;
    assert_eq!(envelope["result"]["delegation_id"], DELEGATION_ID);
    assert_eq!(envelope["result"]["recipient_principal_id"], G_OPERATOR);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
}

async fn step_04_context_pack(
    app: &axum::Router,
    h1: &HumanSession,
    agent_provider: &Ed25519SigningProvider,
    creation: &CreationFixture,
) -> (String, String) {
    let intent_op = human_operation(
        "content-resource-intent.issue",
        "proof.dev/operation/content-resource-intent.issue/v2",
    );
    let intent_input = json!({
        "api_version": "proof.dev/operation/content-resource-intent.issue/v2",
        "creations": creation.resource_intent["creations"],
        "environment_id": "preview",
        "idempotency_key": "019d0000-0000-7000-8000-0000000000b2",
        "intent_id": RESOURCE_INTENT_ID,
        "issued_at": CONTENT_ISSUED_AT,
        "targets": creation.resource_intent["targets"],
    });
    let resp = post_operation(
        app,
        "human",
        intent_op.name.as_str(),
        "v2",
        Some(h1),
        &operation_request_body(&intent_op, &intent_input),
    )
    .await;
    let intent_envelope = expect_success(resp, "H1 issues the creation-slot intent").await;
    assert_eq!(intent_envelope["result"]["intent_id"], RESOURCE_INTENT_ID);
    let intent_digest = artifact_digest(
        ArtifactKind::ContentResourceIntentV1,
        &canonical_bytes(&intent_envelope["result"]),
    )
    .to_string();
    step_04_delegation(app, h1, &intent_digest).await;

    let context_input = json!({
        "api_version": "proof.dev/operation/context.build/v2",
        "context_pack_id": CONTEXT_PACK_ID,
        "created_at": CONTEXT_CREATED_AT,
        "expires_at": CONTEXT_EXPIRES_AT,
        "idempotency_key": "019d0000-0000-7000-8000-0000000000b3",
        "limits": {
            "max_bytes": 65536,
            "max_edits": 7,
            "max_objects": 2,
            "max_validation_attempts": 2,
        },
        "policy_rules": [{
            "disallowed_values": [FORBIDDEN_LEGAL_CLAIM],
            "locale": FR_CA_LOCALE,
            "pointer": "/legal",
        }],
        "resource_intent_digest": intent_digest,
        "resource_intent_id": RESOURCE_INTENT_ID,
    });
    let envelope = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ContextBuildV2,
        input_object(&context_input),
        "delegated G builds the ContextPack",
    )
    .await;
    assert_eq!(envelope["result"]["context_pack_id"], CONTEXT_PACK_ID);
    assert_eq!(envelope["result"]["resource_intent_digest"], intent_digest);
    (
        intent_digest,
        envelope["result"]["context_pack_digest"]
            .as_str()
            .expect("ContextPack digest")
            .to_owned(),
    )
}

// ---------------------------------------------------------------------------
// Step 5: G proposes edits, validates, and submits over dual authentication.
// ---------------------------------------------------------------------------

async fn step_05_agent_changeset_lifecycle(
    app: &axum::Router,
    h1: &HumanSession,
    agent_provider: &Ed25519SigningProvider,
    creation: &CreationFixture,
    resource_intent_digest: &str,
    context_pack_digest: &str,
) -> LiveCreationRun {
    run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetCreateV2,
        input_object(&json!({
            "api_version": "proof.dev/operation/changeset.create/v2",
            "changeset_id": CHANGES_ET_ID,
            "context_pack_digest": context_pack_digest,
            "context_pack_id": CONTEXT_PACK_ID,
            "created_at": CHANGESET_CREATED_AT,
            "idempotency_key": "019d0000-0000-7000-8000-000000000062",
            "intent": "Create two localized resources",
            "resource_intent_digest": resource_intent_digest,
            "resource_intent_id": RESOURCE_INTENT_ID,
        })),
        "G creates the localized ChangeSet",
    )
    .await;
    let first_add = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetAddV2,
        input_object(&creation.expected_add_input),
        "G appends two Object creations and their locale puts",
    )
    .await;
    let initial_edit_ids = first_add["result"]["edit_ids"]
        .as_array()
        .expect("initial Add returns Edit identities")
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(initial_edit_ids.len(), 6);
    let bad_edit_index = creation.expected_add_input["edits"]
        .as_array()
        .unwrap()
        .iter()
        .position(|edit| edit["content"]["legal"] == FORBIDDEN_LEGAL_CLAIM)
        .expect("one initial put carries the prohibited legal claim");
    let bad_edit_id = initial_edit_ids[bad_edit_index].clone();
    let add_result_digest = first_add["committed_anchor"]["result_digest"]
        .as_str()
        .expect("fresh Add response carries its result digest")
        .to_owned();
    assert_eq!(
        proof_remote::registry::operation_effect_digest(&first_add["result"])
            .unwrap()
            .to_string(),
        add_result_digest,
        "the committed Add result digest reproduces from the returned bytes"
    );
    let replay_add = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetAddV2,
        input_object(&creation.expected_add_input),
        "G replays the same Add application key",
    )
    .await;
    assert_eq!(replay_add["result"], first_add["result"]);
    assert_eq!(
        replay_add["committed_anchor"]["result_digest"],
        add_result_digest
    );

    let mut conflicting_add = creation.expected_add_input.clone();
    conflicting_add["edits"][0]["content"]["title"] = json!("Conflicting title");
    let conflict_add = run_agent_operation_problem(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetAddV2,
        input_object(&conflicting_add),
        "proof.idempotency.key_reused",
        "G reuses the Add key with changed input",
    )
    .await;
    assert_eq!(conflict_add["code"], "proof.idempotency.key_reused");

    let validate_input = json!({
        "api_version": "proof.dev/operation/changeset.validate/v2",
        "changeset_id": CHANGES_ET_ID,
    });
    let validation = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetValidateV2,
        input_object(&validate_input),
        "G records the one deterministic policy finding",
    )
    .await;
    assert_eq!(validation["result"]["valid"], false);
    assert_eq!(validation["result"]["attempt"], 1);
    assert_eq!(
        validation["result"]["findings"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        validation["result"]["findings"][0]["code"],
        "proof.validation.prohibited_legal_claim"
    );
    assert_eq!(validation["result"]["findings"][0]["edit_id"], bad_edit_id);
    assert_eq!(validation["result"]["findings"][0]["locale"], FR_CA_LOCALE);
    assert_eq!(validation["result"]["findings"][0]["pointer"], "/legal");
    let invalid_validation_digest = validation["result"]["validation_results_digest"]
        .as_str()
        .expect("invalid validation returns its result digest")
        .to_owned();
    let replay_validation = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetValidateV2,
        input_object(&validate_input),
        "G replays the invalid validation through its derived key",
    )
    .await;
    assert_eq!(replay_validation["result"], validation["result"]);

    let mut repair_edit = creation.expected_add_input["edits"][bad_edit_index].clone();
    repair_edit["content"]["legal"] = json!("Des conditions standard s'appliquent");
    repair_edit["supersedes_edit_id"] = json!(bad_edit_id);
    repair_edit["repair_of_validation_result_digest"] = json!(invalid_validation_digest);
    let repair_input = json!({
        "api_version": "proof.dev/operation/changeset.add/v2",
        "changeset_id": CHANGES_ET_ID,
        "edits": [repair_edit],
        "idempotency_key": REPAIR_ADD_APPLICATION_KEY,
    });
    let repair = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetAddV2,
        input_object(&repair_input),
        "G supersedes the actual rejected Edit under fresh repair evidence",
    )
    .await;
    assert_eq!(repair["result"]["first_ordinal"], 7);
    assert_eq!(repair["result"]["total_edit_count"], 7);
    let repaired_edit_id = repair["result"]["edit_ids"][0]
        .as_str()
        .expect("repair Add returns its assigned Edit identity")
        .to_owned();
    assert_ne!(repaired_edit_id, bad_edit_id);

    let valid = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetValidateV2,
        input_object(&validate_input),
        "G validates the repaired six-leaf proposal",
    )
    .await;
    assert_eq!(valid["result"]["attempt"], 2);
    assert_eq!(
        valid["result"]["previous_validation_result_digest"],
        invalid_validation_digest
    );
    assert_eq!(valid["result"]["valid"], true);
    assert_eq!(valid["result"]["findings"], json!([]));
    let final_validation_digest = valid["result"]["validation_results_digest"]
        .as_str()
        .expect("valid repair returns its result digest")
        .to_owned();
    let replay_valid = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetValidateV2,
        input_object(&validate_input),
        "G replays repaired validation through its derived key",
    )
    .await;
    assert_eq!(replay_valid["result"], valid["result"]);

    let diff = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetDiffV2,
        input_object(&json!({
            "api_version": "proof.dev/operation/changeset.diff/v2",
            "changeset_id": CHANGES_ET_ID,
        })),
        "G inspects the repaired effective leaves",
    )
    .await;
    let effective_edit_ids = diff["result"]["effective_edits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|edit| edit["edit_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        effective_edit_ids.len(),
        6,
        "the superseded attempt is not an effective leaf: {}",
        diff["result"]
    );
    assert!(!effective_edit_ids.contains(bad_edit_id.as_str()));
    assert!(effective_edit_ids.contains(repaired_edit_id.as_str()));

    let submit_input = json!({
        "api_version": "proof.dev/operation/changeset.submit/v2",
        "changeset_id": CHANGES_ET_ID,
        "submitted_at": timestamp_offset(0).to_string(),
    });
    let submitted = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetSubmitV2,
        input_object(&submit_input),
        "G submits the sealed lineage",
    )
    .await;
    assert_eq!(submitted["result"]["status"], "submitted");
    let replay_submit = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetSubmitV2,
        input_object(&submit_input),
        "G replays submit through its derived key",
    )
    .await;
    assert_eq!(replay_submit["result"], submitted["result"]);
    LiveCreationRun {
        initial_edit_ids,
        bad_edit_id,
        invalid_validation_digest,
        repaired_edit_id,
        final_validation_digest,
    }
}

// ---------------------------------------------------------------------------
// Step 6: separation-of-duties rejections for the Human-only approval.
// ---------------------------------------------------------------------------

async fn step_06_separation_of_duties_rejections(
    app: &axum::Router,
    h1: &HumanSession,
    agent_provider: &Ed25519SigningProvider,
) {
    let approve_name = "changeset.approve";
    let approve_major = "v3";

    // G cannot approve: the approval row does not exist on the Agent
    // projection, so the route cross-check rejects before execution.
    let invocation = build_agent_invocation(
        agent_provider,
        AuthorityOperation::ChangesetGetV2,
        input_object(&json!({
            "api_version": "proof.dev/operation/changeset.get/v2",
            "changeset_id": CHANGES_ET_ID,
        })),
    );
    let agent_body = json!({
        "api_version": "proof.dev/http-agent-operation-request/v1",
        "operation": {"name": approve_name, "version": "proof.dev/operation/changeset.approve/v3"},
        "invocation": serde_json::to_value(&invocation).unwrap()
    });
    let resp = post_operation(
        app,
        "agent",
        approve_name,
        approve_major,
        Some(h1),
        &agent_body,
    )
    .await;
    expect_problem(
        resp,
        "proof.input.schema_mismatch",
        "G attempts Human-only approval",
    )
    .await;

    // The initiating Human cannot approve either: H1 lacks content.reviewer,
    // so the decision denies and commits the signed denial alone.
    let op = human_operation(approve_name, "proof.dev/operation/changeset.approve/v3");
    let input = json!({
        "workspace_id": WS_ID,
        "changeset_id": CHANGES_ET_ID,
        "approval_id": "019d0000-0000-7000-8000-0000000000c9",
        "idempotency_key": "019d0000-0000-7000-8000-0000000000ca",
    });
    let resp = post_operation(
        app,
        "human",
        approve_name,
        approve_major,
        Some(h1),
        &operation_request_body(&op, &input),
    )
    .await;
    expect_problem(
        resp,
        "proof.authorization.denied",
        "initiator H1 cannot approve",
    )
    .await;
}

async fn live_content_read(
    app: &axum::Router,
    h2: &HumanSession,
    name: &str,
    input: &Value,
    label: &str,
) -> Value {
    let operation = human_operation(name, &format!("proof.dev/operation/{name}/v1"));
    let response = post_operation(
        app,
        "human",
        name,
        "v1",
        Some(h2),
        &operation_request_body(&operation, input),
    )
    .await;
    expect_success(response, label).await["result"].clone()
}

fn assert_two_object_entries(result: &Value, released: bool) {
    assert_eq!(
        result["state_scope"],
        "committed-workspace-state-not-necessarily-released"
    );
    let entries = result["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry["object_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [CREATED_OBJECT_A_ID, CREATED_OBJECT_B_ID]
    );
    for entry in entries {
        assert_eq!(entry["covered_by_current_release"], released);
        if released {
            assert_eq!(entry["released_revision"], 1);
        } else {
            assert!(entry["released_revision"].is_null());
        }
        assert_eq!(
            entry["head_renditions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|rendition| rendition["locale"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [EN_LOCALE, FR_CA_LOCALE]
        );
    }
}

async fn step_07_live_reads_before_release(
    app: &axum::Router,
    h2: &HumanSession,
    creation: &CreationFixture,
) {
    let schema_page = live_content_read(
        app,
        h2,
        "schema.list",
        &json!({
            "api_version": "proof.dev/operation/schema.list/v1",
            "page_size": 100,
        }),
        "H2 lists the bounded live Schema register",
    )
    .await;
    assert_eq!(
        schema_page["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["schema_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [OBJECT_A_SCHEMA_ID, OBJECT_B_SCHEMA_ID]
    );
    assert!(schema_page["next_cursor"].is_null());

    let first_schema_page_input = json!({
        "api_version": "proof.dev/operation/schema.list/v1",
        "page_size": 1,
    });
    let first_schema_page = live_content_read(
        app,
        h2,
        "schema.list",
        &first_schema_page_input,
        "H2 reads the first sequence-stable Schema page",
    )
    .await;
    let repeated_schema_page = live_content_read(
        app,
        h2,
        "schema.list",
        &first_schema_page_input,
        "H2 repeats the first sequence-stable Schema page",
    )
    .await;
    assert_eq!(repeated_schema_page, first_schema_page);
    assert_eq!(
        first_schema_page["entries"][0]["schema_id"],
        OBJECT_A_SCHEMA_ID
    );
    assert_eq!(first_schema_page["next_cursor"], "1");
    assert_eq!(
        first_schema_page["next_cursor"],
        first_schema_page["entries"][0]["provenance"]["authoritative_sequence"]
            .as_u64()
            .unwrap()
            .to_string()
    );
    let second_schema_page = live_content_read(
        app,
        h2,
        "schema.list",
        &json!({
            "api_version": "proof.dev/operation/schema.list/v1",
            "cursor": first_schema_page["next_cursor"],
            "page_size": 1,
        }),
        "H2 advances the Schema cursor",
    )
    .await;
    assert_eq!(
        second_schema_page["entries"][0]["schema_id"],
        OBJECT_B_SCHEMA_ID
    );
    assert!(second_schema_page["next_cursor"].is_null());

    let exact_schema = live_content_read(
        app,
        h2,
        "schema.list",
        &json!({
            "api_version": "proof.dev/operation/schema.list/v1",
            "page_size": 100,
            "schema_id": OBJECT_B_SCHEMA_ID,
        }),
        "H2 filters the live Schema register by exact identity",
    )
    .await;
    assert_eq!(exact_schema["entries"].as_array().unwrap().len(), 1);
    assert_eq!(exact_schema["entries"][0]["schema_id"], OBJECT_B_SCHEMA_ID);

    for schema_id in [OBJECT_A_SCHEMA_ID, OBJECT_B_SCHEMA_ID] {
        let resource = creation.context_pack["resources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|resource| resource["schema_candidates"][0]["schema_id"] == schema_id)
            .unwrap();
        let schema = live_content_read(
            app,
            h2,
            "schema.get",
            &json!({
                "api_version": "proof.dev/operation/schema.get/v1",
                "schema_id": schema_id,
                "schema_version": 1,
            }),
            "H2 reads an exact authoring Schema",
        )
        .await;
        assert_eq!(schema["schema_id"], schema_id);
        assert_eq!(
            schema["document"],
            resource["schema_candidates"][0]["document"]
        );
    }

    let missing_schema = human_operation("schema.get", "proof.dev/operation/schema.get/v1");
    let missing_schema_input = json!({
        "api_version": "proof.dev/operation/schema.get/v1",
        "schema_id": "missing",
        "schema_version": 1,
    });
    let response = post_operation(
        app,
        "human",
        missing_schema.name.as_str(),
        "v1",
        Some(h2),
        &operation_request_body(&missing_schema, &missing_schema_input),
    )
    .await;
    expect_problem(
        response,
        "proof.schema.not_found",
        "H2 misses an exact Schema",
    )
    .await;

    let oversized_schema_page =
        human_operation("schema.list", "proof.dev/operation/schema.list/v1");
    let oversized_schema_input = json!({
        "api_version": "proof.dev/operation/schema.list/v1",
        "page_size": 101,
    });
    let response = post_operation(
        app,
        "human",
        oversized_schema_page.name.as_str(),
        "v1",
        Some(h2),
        &operation_request_body(&oversized_schema_page, &oversized_schema_input),
    )
    .await;
    expect_problem(
        response,
        "proof.input.schema_mismatch",
        "Schema pages are capped at 100",
    )
    .await;

    let object_ids_input = json!({
        "api_version": "proof.dev/operation/object.list/v1",
        "environment_id": "preview",
        "object_ids": [CREATED_OBJECT_A_ID, CREATED_OBJECT_B_ID],
        "page_size": 100,
    });
    let draft_objects = live_content_read(
        app,
        h2,
        "object.list",
        &object_ids_input,
        "H2 reads both committed Objects before Release",
    )
    .await;
    assert_two_object_entries(&draft_objects, false);

    let first_object_page_input = json!({
        "api_version": "proof.dev/operation/object.list/v1",
        "environment_id": "preview",
        "object_ids": [CREATED_OBJECT_A_ID, CREATED_OBJECT_B_ID],
        "page_size": 1,
    });
    let first_object_page = live_content_read(
        app,
        h2,
        "object.list",
        &first_object_page_input,
        "H2 reads the first sequence-stable Object page",
    )
    .await;
    let repeated_object_page = live_content_read(
        app,
        h2,
        "object.list",
        &first_object_page_input,
        "H2 repeats the first sequence-stable Object page",
    )
    .await;
    assert_eq!(repeated_object_page, first_object_page);
    assert_eq!(
        first_object_page["entries"][0]["object_id"],
        CREATED_OBJECT_A_ID
    );
    assert!(first_object_page["next_cursor"].is_string());
    let second_object_page = live_content_read(
        app,
        h2,
        "object.list",
        &json!({
            "api_version": "proof.dev/operation/object.list/v1",
            "cursor": first_object_page["next_cursor"],
            "environment_id": "preview",
            "object_ids": [CREATED_OBJECT_A_ID, CREATED_OBJECT_B_ID],
            "page_size": 1,
        }),
        "H2 advances the Object cursor",
    )
    .await;
    assert_eq!(
        second_object_page["entries"][0]["object_id"],
        CREATED_OBJECT_B_ID
    );
    assert!(second_object_page["next_cursor"].is_null());

    let schema_filtered = live_content_read(
        app,
        h2,
        "object.list",
        &json!({
            "api_version": "proof.dev/operation/object.list/v1",
            "environment_id": "preview",
            "page_size": 100,
            "schema_id": OBJECT_A_SCHEMA_ID,
        }),
        "H2 filters Objects by exact Schema",
    )
    .await;
    assert_eq!(schema_filtered["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        schema_filtered["entries"][0]["object_id"],
        CREATED_OBJECT_A_ID
    );

    let locale_filtered = live_content_read(
        app,
        h2,
        "object.list",
        &json!({
            "api_version": "proof.dev/operation/object.list/v1",
            "environment_id": "preview",
            "locale": FR_CA_LOCALE,
            "page_size": 100,
        }),
        "H2 filters Objects by exact locale",
    )
    .await;
    assert_eq!(locale_filtered["entries"].as_array().unwrap().len(), 2);
    assert!(
        locale_filtered["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| {
                entry["head_renditions"]
                    .as_array()
                    .is_some_and(|rows| rows.len() == 1 && rows[0]["locale"] == FR_CA_LOCALE)
            })
    );

    let object_filtered = live_content_read(
        app,
        h2,
        "object.list",
        &json!({
            "api_version": "proof.dev/operation/object.list/v1",
            "environment_id": "preview",
            "object_ids": [CREATED_OBJECT_B_ID],
            "page_size": 100,
        }),
        "H2 filters Objects by exact identity",
    )
    .await;
    assert_eq!(object_filtered["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        object_filtered["entries"][0]["object_id"],
        CREATED_OBJECT_B_ID
    );

    let oversized_object_page =
        human_operation("object.list", "proof.dev/operation/object.list/v1");
    let oversized_object_input = json!({
        "api_version": "proof.dev/operation/object.list/v1",
        "environment_id": "preview",
        "object_ids": [CREATED_OBJECT_A_ID, CREATED_OBJECT_B_ID],
        "page_size": 101,
    });
    let response = post_operation(
        app,
        "human",
        oversized_object_page.name.as_str(),
        "v1",
        Some(h2),
        &operation_request_body(&oversized_object_page, &oversized_object_input),
    )
    .await;
    expect_problem(
        response,
        "proof.input.schema_mismatch",
        "Object pages are capped at 100",
    )
    .await;
}

async fn step_07_live_reads_after_release(app: &axum::Router, h2: &HumanSession) {
    let released_objects = live_content_read(
        app,
        h2,
        "object.list",
        &json!({
            "api_version": "proof.dev/operation/object.list/v1",
            "environment_id": "preview",
            "object_ids": [CREATED_OBJECT_A_ID, CREATED_OBJECT_B_ID],
            "page_size": 100,
        }),
        "H2 reads the same Objects after Release",
    )
    .await;
    assert_two_object_entries(&released_objects, true);
}

// ---------------------------------------------------------------------------
// Step 7: H2 approves; G commits idempotently; Edition, Environment, Release.
// ---------------------------------------------------------------------------

async fn step_07_approval_idempotent_commit_edition_environment_release(
    app: &axum::Router,
    h1: &HumanSession,
    h2: &HumanSession,
    agent_provider: &Ed25519SigningProvider,
    creation: &CreationFixture,
) -> ContentDigest {
    let approve_op = human_operation(
        "changeset.approve",
        "proof.dev/operation/changeset.approve/v3",
    );
    let approve_input = json!({
        "workspace_id": WS_ID,
        "changeset_id": CHANGES_ET_ID,
        "approval_id": "019d0000-0000-7000-8000-0000000000d1",
        "idempotency_key": "019d0000-0000-7000-8000-0000000000d2",
    });
    let resp = post_operation(
        app,
        "human",
        approve_op.name.as_str(),
        "v3",
        Some(h2),
        &operation_request_body(&approve_op, &approve_input),
    )
    .await;
    let envelope = expect_success(resp, "H2 records the causal approval").await;
    assert_eq!(envelope["result"]["changeset_id"], CHANGES_ET_ID);
    assert_eq!(envelope["result"]["approval_name"], "editorial");

    let commit_input = json!({
        "api_version": "proof.dev/operation/changeset.commit/v2",
        "changeset_id": CHANGES_ET_ID,
        "committed_at": timestamp_offset(0).to_string(),
        "idempotency_key": "019d0000-0000-7000-8000-0000000000d3",
    });
    let first_commit = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetCommitV2,
        input_object(&commit_input),
        "G commits the approved ChangeSet",
    )
    .await;
    assert_eq!(first_commit["result"]["status"], "committed");
    assert_eq!(
        first_commit["result"]["renditions"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    let resulting_state_digest = first_commit["result"]["resulting_state"]["digest"]
        .as_str()
        .expect("commit returns the resulting state digest")
        .to_owned();
    let replay_commit = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetCommitV2,
        input_object(&commit_input),
        "replayed commit returns identical bytes",
    )
    .await;
    assert_eq!(replay_commit["result"], first_commit["result"]);

    let mut conflicting_commit = commit_input.clone();
    conflicting_commit["committed_at"] = json!(timestamp_offset(1).to_string());
    let conflict_commit = run_agent_operation_problem(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetCommitV2,
        input_object(&conflicting_commit),
        "proof.idempotency.key_reused",
        "G reuses the commit key with changed input",
    )
    .await;
    assert_eq!(conflict_commit["code"], "proof.idempotency.key_reused");

    step_07_live_reads_before_release(app, h2, creation).await;

    run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::EditionCreateV2,
        input_object(&json!({
            "api_version": "proof.dev/operation/edition.create/v2",
            "changeset_id": CHANGES_ET_ID,
            "created_at": timestamp_offset(0).to_string(),
            "edition_id": EDITION_ID,
            "idempotency_key": "019d0000-0000-7000-8000-0000000000d4",
            "resulting_state_digest": resulting_state_digest,
        })),
        "G creates the exact Edition",
    )
    .await;

    let release_input = input_object(&json!({
        "api_version": "proof.dev/operation/release.create/v2",
        "edition_id": EDITION_ID,
        "environment_id": "preview",
        "expected_base_release_id": BASE_RELEASE_ID,
        "idempotency_key": RELEASE_APPLICATION_KEY,
        "proof_id": PROOF_ID,
        "release_id": RELEASE_ID,
        "released_at": timestamp_offset(0).to_string(),
    }));
    let release_create = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ReleaseCreateV2,
        release_input.clone(),
        "G invokes release.create/v2 with an idempotency key",
    )
    .await;
    assert_eq!(release_create["result"]["release_id"], RELEASE_ID);
    let release_digest = release_create["result"]["release_digest"]
        .as_str()
        .expect("Release digest")
        .parse()
        .expect("valid Release digest");
    assert!(release_create["result"]["proof_envelope_digest"].is_string());

    let release_replay = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ReleaseCreateV2,
        release_input.clone(),
        "G reconciles release.create/v2 with a fresh presentation",
    )
    .await;
    assert_eq!(release_replay["result"], release_create["result"]);

    let mut conflicting_release = release_input;
    conflicting_release["released_at"] = json!(timestamp_offset(1).to_string());
    let release_conflict = run_agent_operation_problem(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ReleaseCreateV2,
        conflicting_release,
        "proof.idempotency.key_reused",
        "G cannot reuse the Release key with changed input",
    )
    .await;
    assert_eq!(release_conflict["code"], "proof.idempotency.key_reused");

    step_07_live_reads_after_release(app, h2).await;
    release_digest
}

// ---------------------------------------------------------------------------
// Step 8: outbox advance to delivered preview plus the ready-gated alias.
//
// The synchronous PostgreSQL driver cannot run inside the tokio runtime, so
// the scenario alternates small async route segments with synchronous
// storage/worker phases on the outer thread.
// ---------------------------------------------------------------------------

const PREVIEW_OBJECT_ID: &str = "019d0000-0000-7000-8000-000000000025";
const PREVIEW_LOCALE: &str = "en-US";

fn human_operation(name: &str, version: &str) -> RemoteOperationV1 {
    operation(name, version)
}

struct PreviewFiles {
    environment: String,
    root: std::path::PathBuf,
    rendition_digest: ContentDigest,
    body_value: Value,
}

/// Materializes the exact Release snapshot projection without its ready
/// marker; the marker is written last so the alias resolves only after ready.
fn stage_preview_files(release_digest: &ContentDigest) -> PreviewFiles {
    let environment = format!("ns_preview_{}", std::process::id());
    let root = std::env::temp_dir()
        .join("proof-preview")
        .join(&environment);
    let release_root = root.join(RELEASE_ID);
    std::fs::create_dir_all(release_root.join("objects").join(PREVIEW_OBJECT_ID)).unwrap();

    let body_value = json!({ "title": "North star preview snapshot", "value": 7 });
    let body_bytes = serde_json::to_vec(&body_value).unwrap();
    let rendition_digest = ContentDigest::blake3(*blake3::hash(&body_bytes).as_bytes());
    let relative_path = format!("objects/{PREVIEW_OBJECT_ID}/{PREVIEW_LOCALE}.json");
    std::fs::write(release_root.join(&relative_path), &body_bytes).unwrap();

    let manifest = json!({
        "release_id": RELEASE_ID,
        "release_digest": release_digest.to_string(),
        "edition_digest": fixed_digest(0x88).to_string(),
        "objects": [{
            "object_id": PREVIEW_OBJECT_ID,
            "locale": PREVIEW_LOCALE,
            "rendition_digest": rendition_digest.to_string(),
            "path": relative_path,
        }],
    });
    std::fs::write(
        release_root.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    PreviewFiles {
        environment,
        root,
        rendition_digest,
        body_value,
    }
}

async fn preview_route_get(app: &axum::Router, environment: &str) -> axum::response::Response {
    let uri = format!(
        "/preview/{environment}/releases/{RELEASE_ID}/objects/{PREVIEW_OBJECT_ID}/locales/{PREVIEW_LOCALE}"
    );
    app.clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn hex_of(digest_value: &ContentDigest) -> String {
    digest_value
        .to_string()
        .strip_prefix("blake3:")
        .unwrap_or(&digest_value.to_string())
        .to_owned()
}

// ---------------------------------------------------------------------------
// Step 10 helpers: exact kind-and-digest artifact acquisition over HTTP.
// ---------------------------------------------------------------------------

async fn fetch_artifact(
    app: &axum::Router,
    export_id: &str,
    artifact_kind: &str,
    digest_value: &ContentDigest,
) -> axum::response::Response {
    let uri =
        format!("/api/v1/evidence-exports/{export_id}/artifacts/{artifact_kind}/{digest_value}");
    app.clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn fetch_ok_artifact(
    app: &axum::Router,
    export_id: &str,
    artifact_kind: &str,
    digest_value: &ContentDigest,
) -> Vec<u8> {
    let resp = fetch_artifact(app, export_id, artifact_kind, digest_value).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "artifact {artifact_kind} must resolve by its exact triple"
    );
    response_bytes(resp).await
}

fn root_member_path(kind: &str) -> &'static str {
    match kind {
        "release-artifact-closure" => "content/release-closure.json",
        "authority-fact" => "authority/facts.json",
        "remote-actor-evidence" => "actor/context-evidence.json",
        "remote-authentication-event" => "authentication/event.json",
        "remote-command-input" => "attempt/command-input.json",
        "remote-authenticated-command-envelope" => "attempt/authenticated-command-envelope.json",
        other => panic!("unknown root kind {other}"),
    }
}

fn nested_member_path(kind: &str, digest_value: &ContentDigest) -> String {
    format!(
        "content/artifacts/{kind}/blake3/{}.json",
        hex_of(digest_value)
    )
}

// ---------------------------------------------------------------------------
// The complete remote north star: alternating async/sync phases.
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn north_star_two_humans_and_one_agent_end_to_end_over_http_and_postgresql() {
    let started = Instant::now();

    // All PostgreSQL setup happens synchronously before any tokio runtime
    // exists because the synchronous driver cannot connect or transact inside
    // `block_on`.
    let db = TestDb::new();
    seed_human_identity(&db, H1_REQUESTER, H1_BINDING_ID, H1_SUBJECT, 2);
    let h2_identity = seed_human_identity(&db, H2_APPROVER, H2_BINDING_ID, H2_SUBJECT, 2);
    seed_principal_status(&db, H1_REQUESTER, false, 3);
    seed_principal_status(&db, H2_APPROVER, false, 3);
    seed_principal_status(&db, G_OPERATOR, true, 3);
    seed_role_assignment(&db, H1_REQUESTER, Role::ContentRequester, 0x11);
    seed_role_assignment(&db, H1_REQUESTER, Role::IdentityAdmin, 0x12);
    seed_role_assignment(&db, H1_REQUESTER, Role::EnvironmentAdmin, 0x13);
    seed_role_assignment(&db, H2_APPROVER, Role::ContentReviewer, 0x21);
    seed_role_assignment(&db, H2_APPROVER, Role::EvidenceAuditor, 0x22);
    seed_role_assignment(&db, H2_APPROVER, Role::EnvironmentActivator, 0x23);
    let authority_provider = Ed25519SigningProvider::from_secret_bytes(&[0x11_u8; 32]);
    db.seed_authority_root(&authority_provider.metadata().unwrap().key_id);
    let agent_provider = Ed25519SigningProvider::from_secret_bytes(&[0x33_u8; 32]);
    let creation = build_creation_inputs();

    // A dedicated worker connection is opened outside the async runtime.
    let mut worker_runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WS_ID.parse().unwrap(),
        Duration::from_secs(60),
    ))
    .expect("connect worker runtime");
    worker_runtime
        .client_mut()
        .batch_execute(&format!("SET search_path TO \"{}\"", db.schema))
        .unwrap();

    let issuer = db.state.issuer.clone();
    let app = router(db.state.clone());

    seed_live_agent_binding(&db, &agent_provider, &authority_provider);

    // Establish live identities and authority before executing the Agent
    // lifecycle against the pre-existing content and Release baseline.
    let (h1, h2) = {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            step_01_capabilities(&app).await;
            let h1 = login_human(&app, &issuer, H1_SUBJECT, H1_REQUESTER).await;
            let h2 = login_human(&app, &issuer, H2_SUBJECT, H2_APPROVER).await;
            step_03_workspace_init_and_role_assignment(&app, &h1).await;
            (h1, h2)
        })
    };
    seed_native_baseline(&db, &creation);

    // Segment 1: ContextPack, Agent lifecycle under separation of duties,
    // approval, commit, Edition, and Release creation.
    let (live_release_digest, live_creation) = {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let (resource_intent_digest, context_pack_digest) =
                step_04_context_pack(&app, &h1, &agent_provider, &creation).await;
            let live_creation = step_05_agent_changeset_lifecycle(
                &app,
                &h1,
                &agent_provider,
                &creation,
                &resource_intent_digest,
                &context_pack_digest,
            )
            .await;
            step_06_separation_of_duties_rejections(&app, &h1, &agent_provider).await;
            let release_digest = step_07_approval_idempotent_commit_edition_environment_release(
                &app,
                &h1,
                &h2,
                &agent_provider,
                &creation,
            )
            .await;
            (release_digest, live_creation)
        })
    };

    db.assert_creation_lifecycle(&creation.expected_add_input, &live_creation);
    let producer_inputs = db.producer_input_snapshot();
    // P-0013's producer-storage contract derives export roots from the live
    // Release. It must not manufacture or rewrite semantic lifecycle records.
    let fixture = materialize_live_attempt(&db, &creation);
    assert_eq!(db.producer_input_snapshot(), producer_inputs);
    assert_eq!(fixture.release_v2_digest, live_release_digest);

    // Synchronous phase: inspect the delivery committed atomically with the
    // Release, then stage the HTTP projection.
    let delivery = db.release_delivery();
    assert_eq!(
        uuid::Uuid::parse_str(&delivery.event_id)
            .unwrap()
            .get_version_num(),
        7
    );
    assert_eq!(
        uuid::Uuid::parse_str(&delivery.delivery_id)
            .unwrap()
            .get_version_num(),
        7
    );
    assert!(delivery.workspace_transaction_sequence > 0);
    assert_eq!(delivery.ordinal, 0);
    assert_eq!(delivery.ordering_key, format!("preview:{WS_ID}:preview"));
    assert!(delivery.stream_sequence > 0);
    assert_eq!(delivery.effect_digest, live_release_digest.to_string());
    assert!(delivery.payload_digest.is_some());
    assert_eq!(delivery.artifact_kind.as_deref(), Some("release_v2"));
    assert_eq!(
        delivery.artifact_digest.as_deref(),
        Some(delivery.effect_digest.as_str())
    );
    assert_eq!(delivery.destination_configuration_version, 1);
    assert_eq!(
        delivery.destination_configuration_digest,
        fixed_digest(0x44).to_string()
    );
    assert_eq!(
        delivery.correlation_id.as_deref(),
        Some(HTTP_CORRELATION_ID)
    );
    assert_eq!(delivery.status, "pending");
    assert!(delivery.next_attempt_scheduled);
    let staged = stage_preview_files(&live_release_digest);

    // Segment 2: the alias stays pending before the ready gate.
    {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let resp = preview_route_get(&app, &staged.environment).await;
            expect_problem(
                resp,
                "proof.dependency.unavailable",
                "preview alias stays pending before ready",
            )
            .await;
        });
    }

    // Synchronous phase: claim, materialize, acknowledge, and confirm the
    // delivered generation plus the drained queue.
    let worker = OutboxWorker::new(WorkerConfig::new(dsn()));
    let claims = worker
        .claim_due_work(&mut worker_runtime)
        .expect("claim the preview delivery");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].event_id, delivery.event_id);
    assert_eq!(claims[0].delivery_id, delivery.delivery_id);
    assert_eq!(claims[0].event_type, "preview.release");
    assert_eq!(claims[0].generation, 1);
    assert_eq!(claims[0].effect_digest, live_release_digest);

    let adapter_root = std::env::temp_dir().join(format!(
        "proof-north-star-preview-worker-{}",
        std::process::id()
    ));
    let adapter = PreviewAdapter::new(&adapter_root);
    let blob_bytes = fixture.release_v2_bytes.clone();
    let blob = PreviewBlobV1 {
        key: format!(
            "artifacts/release_v2/blake3/{}",
            hex_of(&fixture.release_v2_digest)
        ),
        kind: "release_v2".to_owned(),
        length: byte_len(&blob_bytes),
        digest: fixture.release_v2_digest,
        bytes: blob_bytes,
    };
    let snapshot = PreviewSnapshotV1 {
        release_id: RELEASE_ID.to_owned(),
        release_sequence: u64::try_from(delivery.stream_sequence).unwrap(),
        release_digest: claims[0].effect_digest,
        edition_digest: claims[0].payload_digest.expect("Edition digest"),
        environment_config_digest: claims[0].destination_configuration_digest,
        proof_digest: fixed_digest(0x89),
        blobs: vec![blob],
    };
    let worker_manifest = adapter
        .materialize_snapshot(&snapshot)
        .expect("materialize");
    assert_eq!(
        worker
            .acknowledge(
                &mut worker_runtime,
                &claims[0],
                worker_manifest.manifest_digest
            )
            .expect("acknowledge"),
        AcknowledgeOutcome::Acknowledged
    );
    assert_eq!(
        db.delivery_status(&delivery.event_id, &delivery.delivery_id, 1),
        "delivered"
    );
    assert!(
        worker
            .claim_due_work(&mut worker_runtime)
            .expect("second claim is empty")
            .is_empty()
    );
    let resolved = adapter.resolve_ready(RELEASE_ID).expect("ready resolves");
    assert_eq!(resolved, worker_manifest);
    let _ = std::fs::remove_dir_all(&adapter_root);

    // Write the ready marker last; the exact snapshot becomes visible only now.
    std::fs::write(staged.root.join(RELEASE_ID).join("ready"), b"").unwrap();

    // Segment 3: the alias resolves over HTTP with the exact snapshot.
    {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let resp = preview_route_get(&app, &staged.environment).await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.headers()
                    .get(header::CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("private, no-store")
            );
            assert_eq!(
                resp.headers()
                    .get(header::ETAG)
                    .and_then(|v| v.to_str().ok()),
                Some(format!("\"{}\"", staged.rendition_digest).as_str())
            );
            let served = response_json(resp).await;
            assert_eq!(served, staged.body_value);
        });
    }

    // Segment 4: keyed evidence.export/v2 capture through the live route.
    let (route_result, route_result_digest) = {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        let input = export_input(&fixture.release_v2_digest);
        let op = evidence_export_operation();
        let h2_session = {
            let login_runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
            login_runtime.block_on(login_human(&app, &issuer, H2_SUBJECT, H2_APPROVER))
        };
        runtime.block_on(async {
            let resp = post_operation(
                &app,
                "human",
                op.name.as_str(),
                "v2",
                Some(&h2_session),
                &operation_request_body(&op, &input),
            )
            .await;
            let envelope = expect_success(resp, "H2 captures evidence.export/v2").await;
            assert_eq!(envelope["result"]["status"], "pending");
            assert_eq!(
                envelope["result"]["application_key"],
                EXPORT_APPLICATION_KEY
            );
            (
                envelope["result"].clone(),
                envelope["committed_anchor"]["result_digest"].clone(),
            )
        })
    };

    // Synchronous phase: same-key typed replay, pending projection, assembly
    // worker, ready projection, and capture-to-fixture binding checks.
    let input = export_input(&fixture.release_v2_digest);
    let first_result = typed_export_create(&db, &input);
    assert_eq!(first_result.status, EvidenceExportStatusKind::Pending);
    let first_bytes = canonical_bytes(&serde_json::to_value(&first_result).unwrap());
    let export_id = first_result.export_id.clone();

    let pending = typed_export_status(&db, &export_id);
    assert_eq!(pending.status, EvidenceExportStatusKind::Pending);
    assert!(pending.bundle_descriptor_digest.is_none());
    assert!(pending.manifest_digest.is_none());
    assert_eq!(pending.artifact_count, 0);

    let capture_bytes = db.read_export_capture_bytes(&export_id);
    let capture: proof_remote::EvidenceExportCaptureV2 =
        serde_json::from_slice(&capture_bytes).unwrap();
    assert_eq!(
        capture
            .closure_bindings
            .remote_authority
            .target_decision_digest,
        fixture.target_decision_digest
    );
    assert_eq!(
        capture
            .closure_bindings
            .remote_authority
            .target_consequence_digest,
        fixture.target_consequence_digest
    );
    assert_eq!(
        capture.closure_bindings.cross_links.result_digest,
        fixture.result_digest
    );
    assert_eq!(
        capture
            .closure_bindings
            .cross_links
            .release_policy_decision_digest,
        fixture.release_policy_decision_digest
    );
    assert_eq!(
        capture.closure_bindings.cross_links.application_key,
        RELEASE_APPLICATION_KEY
    );
    // The disclosure binds the Human export caller's subject commitment (H2),
    // not the selected attempt's requester (H1): capture metadata is
    // pre-attempt and unauthenticated by contract.
    assert_eq!(
        capture.disclosures[0].commitment_digest,
        h2_identity.subject_commitment
    );

    // The exported cross-links bind the retained Agent attempt material, not
    // the Human export caller (H2): command/envelope digests match the stored
    // companions, identities match the signed decision's agent authorization,
    // and the environment-config link matches the closure entrypoint.
    assert_eq!(
        capture.closure_bindings.cross_links.command_digest,
        fixture.command_input_digest
    );
    assert_eq!(
        capture
            .closure_bindings
            .cross_links
            .authenticated_command_envelope_digest,
        fixture.command_envelope_digest
    );
    assert_eq!(
        capture.closure_bindings.cross_links.requesting_principal_id,
        H1_REQUESTER
    );
    assert_eq!(
        capture.closure_bindings.cross_links.operating_principal_id,
        G_OPERATOR
    );
    assert_eq!(
        capture.closure_bindings.cross_links.delegation_id,
        DELEGATION_ID
    );
    assert_eq!(
        capture.closure_bindings.cross_links.presentation_id,
        fixture.presentation_id
    );

    let worker = ExportWorker::new();
    assert_eq!(worker.run_once(&db.state).expect("worker run_once"), 1);
    assert_eq!(worker.run_once(&db.state).expect("second run_once"), 0);

    let ready = typed_export_status(&db, &export_id);
    assert_eq!(ready.status, EvidenceExportStatusKind::Ready);
    let bundle_digest = ready.bundle_descriptor_digest.expect("ready bundle digest");
    let ready_manifest_digest = ready.manifest_digest.expect("ready manifest digest");
    assert_eq!(
        ready.artifact_count,
        u64::try_from(6 + fixture.nested.len()).unwrap()
    );
    assert!(ready.total_included_bytes > 0);

    let bundle_descriptor = build_bundle_descriptor(&capture).unwrap();
    let manifest_value = serde_json::to_value(build_manifest(&capture).unwrap()).unwrap();
    let expected_bundle = domain_digest(
        REMOTE_EVIDENCE_BUNDLE_DIGEST_CONTEXT,
        &canonical_bytes(&serde_json::to_value(&bundle_descriptor).unwrap()),
    );
    let expected_manifest = domain_digest(
        REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT,
        &canonical_bytes(&manifest_value),
    );
    assert_eq!(bundle_digest, expected_bundle);
    assert_eq!(ready_manifest_digest, expected_manifest);

    // Segment 5: byte-bound route-level replay, exact-triple artifact
    // acquisition without cross-kind aliases, and the unknown-export profile.
    let fetched_members = {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let op = evidence_export_operation();
            let h2_session = login_human(&app, &issuer, H2_SUBJECT, H2_APPROVER).await;

            let resp = post_operation(
                &app,
                "human",
                op.name.as_str(),
                "v2",
                Some(&h2_session),
                &operation_request_body(&op, &input),
            )
            .await;
            let replay_envelope = expect_success(resp, "route-level export replay").await;
            assert_eq!(replay_envelope["result"], route_result);
            assert_eq!(
                replay_envelope["committed_anchor"]["result_digest"],
                route_result_digest
            );

            // Reserved descriptors stay hidden while pending was asserted
            // above; once ready both acquire by their exact reserved digests.
            let mut members: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            let bundle_bytes = fetch_ok_artifact(&app, &export_id, "bundle", &bundle_digest).await;
            members.insert("bundle.json".to_owned(), bundle_bytes);
            let manifest_bytes =
                fetch_ok_artifact(&app, &export_id, "manifest", &ready_manifest_digest).await;
            members.insert("manifest.json".to_owned(), manifest_bytes.clone());

            let roots: Vec<(String, ContentDigest)> = vec![
                (
                    "release-artifact-closure".to_owned(),
                    fixture.closure_digest,
                ),
                ("authority-fact".to_owned(), fixture.record_set_digest),
                (
                    "remote-actor-evidence".to_owned(),
                    fixture.actor_evidence_digest,
                ),
                (
                    "remote-authentication-event".to_owned(),
                    fixture.authentication_event_digest,
                ),
                (
                    "remote-command-input".to_owned(),
                    fixture.command_input_digest,
                ),
                (
                    "remote-authenticated-command-envelope".to_owned(),
                    fixture.command_envelope_digest,
                ),
            ];
            for (kind, digest_value) in &roots {
                let bytes = fetch_ok_artifact(&app, &export_id, kind, digest_value).await;
                members.insert(root_member_path(kind).to_owned(), bytes);
            }
            for (kind, digest_value) in &fixture.nested {
                let bytes = fetch_ok_artifact(&app, &export_id, kind, digest_value).await;
                let expected = fixture
                    .nested_bodies
                    .iter()
                    .find(|(expected_kind, expected_digest, _)| {
                        expected_kind == kind && expected_digest == digest_value
                    })
                    .expect("materialized nested artifact body");
                assert_eq!(bytes, expected.2);
                members.insert(nested_member_path(kind, digest_value), bytes);
            }

            // A digest under another kind is not an alias.
            let release_digest = fixture
                .nested
                .iter()
                .find(|(kind, _)| kind == "release_v2")
                .map(|(_, digest_value)| *digest_value)
                .unwrap();
            let resp = fetch_artifact(&app, &export_id, "proof_envelope_v1", &release_digest).await;
            expect_problem(
                resp,
                "proof.resource.not_found",
                "wrong-kind digest alias is rejected",
            )
            .await;

            let resp = fetch_artifact(
                &app,
                "019d0000-0000-7000-8000-0000000000ff",
                "release_v2",
                &release_digest,
            )
            .await;
            expect_problem(
                resp,
                "proof.resource.not_found",
                "unknown export is rejected",
            )
            .await;

            // Every declared membership entry matches its fetched bytes exactly.
            let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
            for member in manifest["membership"].as_array().expect("membership") {
                let path = member["member_path"].as_str().unwrap();
                let expected_length = member["byte_length"].as_u64().unwrap();
                let bytes = members
                    .get(path)
                    .unwrap_or_else(|| panic!("member {path} fetched"));
                assert_eq!(byte_len(bytes), expected_length, "member {path} length");
            }
            members
        })
    };

    // The same-key typed replay after assembly returns byte-identical
    // create-result bytes.
    let replayed_result = typed_export_create(&db, &input);
    let replayed_bytes = canonical_bytes(&serde_json::to_value(&replayed_result).unwrap());
    assert_eq!(
        first_bytes, replayed_bytes,
        "same-key replay must return byte-identical create-result bytes even post-assembly"
    );

    // Final phase: offline verification of the fetched logical member map.
    // This consumes no producer state, network, session, or private key.
    let trust = build_trust_inputs(&fixture);

    // The P8 authority suffix verifies independently under explicit trust:
    // signature, signer key, sequence contiguity, predecessor linkage, and
    // head coherence all reproduce from the fetched envelopes alone.
    let record_set_value: Value =
        serde_json::from_slice(&fetched_members["authority/facts.json"]).unwrap();
    let envelopes: Vec<Vec<u8>> = record_set_value["records"]
        .as_array()
        .expect("record envelopes")
        .iter()
        .map(canonical_bytes)
        .collect();
    let suffix = verify_remote_authority_suffix(&RemoteAuthoritySuffixInput {
        envelopes: &envelopes,
        initial_root_key_id: &fixture.authority_key_id,
        initial_head: fixture.initial_authority_head,
    })
    .expect("fetched authority suffix verifies under caller-pinned trust");
    assert_eq!(suffix.verified_records.len(), envelopes.len());
    assert_eq!(
        suffix.included_head.sequence,
        fixture.initial_authority_head.sequence + u64::try_from(envelopes.len()).unwrap()
    );

    // The composed remote-evidence verifier consumes only the fetched member
    // map and the caller-supplied policy input.
    let report = verify_remote_evidence_v2(&fetched_members, &trust.input);
    println!(
        "offline verification report: status={:?} scenario={:?} reasons={:?}",
        report.status, report.scenario, report.reason_codes
    );

    // The producer binds every attempt link from the captured attempt material
    // (command/envelope digests, Agent authorization identities, closure
    // entrypoint environment config, recomputed public input projection), so
    // the composed offline leg classifies the export Complete.
    assert_eq!(report.status, VerificationStatus::Complete);
    assert_eq!(report.reason_codes, vec![VerificationReasonCode::Verified]);

    let _ = std::fs::remove_dir_all(&staged.root);
    println!(
        "north-star remote duration: {} ms",
        started.elapsed().as_millis()
    );
}
