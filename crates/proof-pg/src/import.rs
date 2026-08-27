//! Verified SQLite-to-PostgreSQL import (contract §"Migration and projection
//! rebuild").

use std::time::SystemTime;

use postgres::IsolationLevel;
use proof_canonical::{
    ObjectStateReference, canonicalize, digest, known_state_digest_with_objects,
};
use proof_domain::{ArtifactKind, ContentDigest, SchemaId, SchemaVersion, WorkspaceId};
use proof_remote::{AuthorityHeadV1, derive_key_digest};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    PgError,
    projection::{
        ensure_projection_tables, parse_object_fact, parse_schema_fact_id,
        rebuild_generation_in_transaction, swap_active_generation_in_transaction,
        verify_canonical_digest,
    },
    schema::ALL_TABLE_DDL,
    wiring::PgRuntime,
};

/// Consumes verified canonical facts via the [`proof_local`] read API,
/// reconstructs chains, rebuilds projections, compares authority heads and
/// Known State, and cuts over atomically (contract §"Migration and projection
/// rebuild").
///
/// Copying unverified SQLite rows is never sufficient.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SqliteToPostgresImporter;

impl SqliteToPostgresImporter {
    /// Constructs the importer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Imports the source Workspace into the target PostgreSQL runtime.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Import`] when chain reconstruction, projection
    /// rebuild, or head/Known-State comparison fails.
    pub fn import(
        &self,
        source: &proof_local::LocalWorkspace,
        target: &mut PgRuntime,
    ) -> Result<ImportReport, PgError> {
        let source =
            read_verified_source(source).map_err(|error| PgError::Import(error.to_string()))?;
        if source.workspace_id != target.config().workspace_id {
            return Err(PgError::Import(format!(
                "source Workspace `{}` disagrees with target Workspace `{}`",
                source.workspace_id,
                target.config().workspace_id
            )));
        }

        ensure_schema(target.client_mut())?;
        ensure_projection_tables(target.client_mut())?;

        // One serializable transaction commits the imported state, the rebuilt
        // projection, the single active pointer, and the cutover together; the
        // public read handle observes the imported state only after commit.
        let mut transaction = target
            .client_mut()
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .read_only(false)
            .start()
            .map_err(|error| PgError::Import(error.to_string()))?;

        insert_workspace_head(&mut transaction, &source)?;
        insert_authority_records(&mut transaction, &source)?;
        insert_facts(&mut transaction, &source)?;

        let generation = rebuild_generation_in_transaction(&mut transaction)
            .map_err(|error| PgError::Import(error.to_string()))?;
        swap_active_generation_in_transaction(&mut transaction, &generation)
            .map_err(|error| PgError::Import(error.to_string()))?;

        // Compare reconstructed heads and Known State against the source.
        let authority_heads_match = generation.heads.authority_head == Some(source.authority_head);
        let known_state_matches = generation.state_digest == source.state_digest;
        if !authority_heads_match {
            return Err(PgError::Import(
                "the reconstructed authority head disagrees with the source".to_owned(),
            ));
        }
        if !known_state_matches {
            return Err(PgError::Import(
                "the reconstructed Known State digest disagrees with the source".to_owned(),
            ));
        }

        transaction
            .commit()
            .map_err(|error| PgError::Import(error.to_string()))?;

        Ok(ImportReport {
            facts_consumed: source.facts_consumed(),
            chains_reconstructed: source.chains_reconstructed(),
            projections_rebuilt: 1,
            authority_heads_match,
            known_state_matches,
            cutover_atomic: true,
        })
    }
}

/// The closed import result (contract §"Migration and projection rebuild").
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportReport {
    /// Verified canonical facts consumed from the SQLite source.
    pub facts_consumed: u64,
    /// Causal chains reconstructed from those facts.
    pub chains_reconstructed: u64,
    /// Projection generations rebuilt.
    pub projections_rebuilt: u64,
    /// Whether the reconstructed authority head matches the source.
    pub authority_heads_match: bool,
    /// Whether the reconstructed Known State digest matches the source.
    pub known_state_matches: bool,
    /// Whether the network-facing cutover was atomic.
    pub cutover_atomic: bool,
}

/// Ensures every authoritative table and the derived projection tables exist.
fn ensure_schema(client: &mut postgres::Client) -> Result<(), PgError> {
    for ddl in ALL_TABLE_DDL {
        client
            .batch_execute(ddl)
            .map_err(|error| PgError::Import(error.to_string()))?;
    }
    client
        .batch_execute(crate::migration::SESSION_BOUNDARY_V2_DDL)
        .map_err(|error| PgError::Import(error.to_string()))?;
    client
        .batch_execute(crate::migration::DELIVERY_STATE_V3_DDL)
        .map_err(|error| PgError::Import(error.to_string()))?;

    let current = crate::migration::workspace_global_idempotency_migration_v5();
    let version = i32::try_from(current.version)
        .map_err(|_| PgError::Import("current migration version exceeds INTEGER".to_owned()))?;
    client
        .execute(
            "INSERT INTO migration_head (
                 singleton, version, name, script_digest, phase,
                 actor, tool_version, started_at, verified_at
             ) VALUES (1, $1, $2, $3, 'verified', 'proof-pg-import', $4, now(), now())",
            &[
                &version,
                &current.name,
                &current.digest.to_string(),
                &env!("CARGO_PKG_VERSION"),
            ],
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    Ok(())
}

/// One verified canonical fact read from the SQLite source.
#[derive(Clone)]
struct ImportedFact {
    fact_id: String,
    fact_kind: String,
    authority_sequence: i64,
    fact_digest: ContentDigest,
    body: Vec<u8>,
}

impl ImportedFact {
    /// Reconstructs the Schema reference from the fact identity and digest.
    fn schema_ref(&self) -> Result<(SchemaId, SchemaVersion, ContentDigest), PgError> {
        let (schema_id, schema_version) = parse_schema_fact_id(&self.fact_id)?;
        Ok((schema_id, schema_version, self.fact_digest))
    }

    /// Reconstructs the Object state reference from the fact body and digest.
    fn object_ref(&self) -> Result<ObjectStateReference, PgError> {
        let value: Value = serde_json::from_slice(&self.body)
            .map_err(|error| PgError::Import(error.to_string()))?;
        parse_object_fact(&value, self.fact_digest)
            .map_err(|error| PgError::Import(error.to_string()))
    }
}

/// One verified local authority record read from the SQLite source.
struct ImportedAuthorityRecord {
    authority_sequence: i64,
    workspace_id: String,
    record_digest: ContentDigest,
    payload_type: String,
    payload: Vec<u8>,
    predecessor_digest: Option<ContentDigest>,
}

/// The complete verified source snapshot consumed by the import.
struct VerifiedSource {
    workspace_id: WorkspaceId,
    authoritative_sequence: u64,
    release_sequence: u64,
    state_digest: ContentDigest,
    authority_head: AuthorityHeadV1,
    authority_records: Vec<ImportedAuthorityRecord>,
    facts: Vec<ImportedFact>,
}

impl VerifiedSource {
    fn facts_consumed(&self) -> u64 {
        u64::try_from(self.facts.len()).unwrap_or(u64::MAX)
    }

    fn chains_reconstructed(&self) -> u64 {
        let authority = u64::try_from(self.authority_records.len()).unwrap_or(u64::MAX);
        let facts = self.facts_consumed();
        authority.saturating_add(facts)
    }
}

/// Reads and re-verifies every canonical fact, authority record, and the Known
/// State from the SQLite source via the [`proof_local`] read surface.
#[allow(clippy::too_many_lines)]
fn read_verified_source(source: &proof_local::LocalWorkspace) -> Result<VerifiedSource, PgError> {
    let connection = source
        .open_database()
        .map_err(|error| PgError::Import(format!("open source database: {error}")))?;

    let workspace_id = read_workspace_id(&connection)?;
    let (state_api_version, authoritative_sequence, state_digest) = read_known_state(&connection)?;
    let authority_records = read_authority_records(&connection, workspace_id)?;
    let last_record = authority_records
        .last()
        .ok_or_else(|| PgError::Import("the source has no authority records".to_owned()))?;
    let authority_head = AuthorityHeadV1 {
        sequence: u64::try_from(last_record.authority_sequence)
            .map_err(|_| PgError::Import("authority sequence is negative".to_owned()))?,
        record_digest: last_record.record_digest,
    };

    let schemas = read_schema_facts(&connection)?;
    let objects = read_object_facts(&connection)?;
    let renditions = read_rendition_facts(&connection)?;
    let releases = read_release_facts(&connection)?;

    // System facts consumed by projection rebuilds (Known State head plus its
    // artifact chain), verified against the source tables directly.
    let mut system_facts = Vec::new();
    {
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/known-state-head/v1",
            "authoritative_sequence": authoritative_sequence,
            "known_state_api_version": state_api_version,
            "state_digest": state_digest.to_string(),
        });
        let canonical = canonicalize(&body).map_err(|error| PgError::Import(error.to_string()))?;
        system_facts.push(ImportedFact {
            fact_id: "known_state/head".to_owned(),
            fact_kind: "known_state_head".to_owned(),
            authority_sequence: i64::try_from(authoritative_sequence)
                .map_err(|_| PgError::Import("sequence overflow".to_owned()))?,
            fact_digest: derive_key_digest(
                "proof:parity:known-state-head:v1",
                canonical.as_bytes(),
            ),
            body: canonical.as_bytes().to_vec(),
        });
    }
    if state_api_version == proof_application::KNOWN_STATE_V2_API_VERSION {
        let mut statement = connection
            .prepare(
                "SELECT api_version, authoritative_sequence, state_digest
                 FROM known_state_artifacts WHERE authoritative_sequence < ?1
                 ORDER BY authoritative_sequence",
            )
            .map_err(|error| PgError::Import(error.to_string()))?;
        let rows = statement
            .query_map(
                [i64::try_from(authoritative_sequence)
                    .map_err(|_| PgError::Import("sequence overflow".to_owned()))?],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .map_err(|error| PgError::Import(error.to_string()))?;
        for row in rows {
            let (artifact_api_version, sequence, digest_text) =
                row.map_err(|error| PgError::Import(error.to_string()))?;
            let artifact_sequence = u64::try_from(sequence)
                .map_err(|_| PgError::Import("negative artifact sequence".to_owned()))?;
            let body = serde_json::json!({
                "api_version": "proof.dev/parity/known-state-artifact/v1",
                "artifact_api_version": artifact_api_version,
                "authoritative_sequence": artifact_sequence,
                "state_digest": digest_text,
            });
            let canonical =
                canonicalize(&body).map_err(|error| PgError::Import(error.to_string()))?;
            system_facts.push(ImportedFact {
                fact_id: format!("known_state_artifact/{sequence:020}"),
                fact_kind: "known_state_artifact".to_owned(),
                authority_sequence: sequence,
                fact_digest: derive_key_digest(
                    "proof:parity:known-state-artifact:v1",
                    canonical.as_bytes(),
                ),
                body: canonical.as_bytes().to_vec(),
            });
        }
    }

    // Cross-check the recorded Known State against the re-verified facts.
    let mut facts = Vec::with_capacity(
        schemas.len() + objects.len() + renditions.len() + releases.len() + system_facts.len(),
    );
    facts.extend(schemas.iter().cloned());
    facts.extend(objects.iter().cloned());
    facts.extend(renditions.iter().cloned());
    facts.extend(releases.iter().cloned());
    facts.extend(system_facts.iter().cloned());

    // Verify the content sequence covers exactly 1..=authoritative_sequence.
    let content_sequence = u64::try_from(schemas.len() + objects.len() + renditions.len())
        .map_err(|_| PgError::Import("content sequence overflow".to_owned()))?;
    if content_sequence != authoritative_sequence {
        return Err(PgError::Import(format!(
            "source Known State sequence {authoritative_sequence} disagrees with {content_sequence} verified content facts"
        )));
    }

    let schema_refs = schemas
        .iter()
        .map(ImportedFact::schema_ref)
        .collect::<Result<Vec<_>, _>>()?;
    let object_refs = objects
        .iter()
        .map(ImportedFact::object_ref)
        .collect::<Result<Vec<_>, _>>()?;
    let reproduced = if state_api_version == proof_application::KNOWN_STATE_V1_API_VERSION {
        known_state_digest_with_objects(
            workspace_id,
            authoritative_sequence,
            &schema_refs,
            &object_refs,
        )
        .map_err(|error| PgError::Import(error.to_string()))?
    } else {
        let locale_refs = read_locale_state_refs(&connection)?;
        let previous_reference = read_previous_known_state(&connection, authoritative_sequence)?;
        let manifest = proof_canonical::known_state_v2_manifest(
            workspace_id,
            authoritative_sequence,
            &schema_refs,
            &object_refs,
            &locale_refs,
            &previous_reference,
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
        digest(ArtifactKind::KnownStateV2, &manifest)
    };
    if reproduced != state_digest {
        return Err(PgError::Import(
            "the source Known State digest does not reproduce from verified facts".to_owned(),
        ));
    }

    let release_sequence = releases
        .iter()
        .map(|fact| fact.authority_sequence)
        .max()
        .map_or(0, |value| u64::try_from(value).unwrap_or(0));

    Ok(VerifiedSource {
        workspace_id,
        authoritative_sequence,
        release_sequence,
        state_digest,
        authority_head,
        authority_records,
        facts,
    })
}

fn read_workspace_id(connection: &Connection) -> Result<WorkspaceId, PgError> {
    let workspace_id: String = connection
        .query_row(
            "SELECT workspace_id FROM workspace_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    workspace_id
        .parse()
        .map_err(|error| PgError::Import(format!("invalid source Workspace identity: {error}")))
}

fn read_known_state(connection: &Connection) -> Result<(String, u64, ContentDigest), PgError> {
    let (api_version, sequence, raw_digest): (String, i64, String) = connection
        .query_row(
            "SELECT api_version, authoritative_sequence, state_digest
             FROM known_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let sequence = u64::try_from(sequence)
        .map_err(|_| PgError::Import("source Known State sequence is negative".to_owned()))?;
    let state_digest = raw_digest
        .parse::<ContentDigest>()
        .map_err(|error| PgError::Import(format!("invalid source Known State digest: {error}")))?;
    Ok((api_version, sequence, state_digest))
}

/// Reads the highest rendition head per (Object, locale) at or below `sequence`.
#[allow(clippy::too_many_lines)]
fn read_locale_state_refs(
    connection: &Connection,
) -> Result<Vec<proof_canonical::LocaleStateReference>, PgError> {
    let mut statement = connection
        .prepare(
            "SELECT object_id, locale, MAX(revision), manifest_json, rendition_digest
             FROM object_locale_revisions GROUP BY object_id, locale",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    let mut refs = Vec::new();
    for row in rows {
        let (object_id, locale, manifest_json, rendition_digest_text) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let manifest: Value = serde_json::from_str(&manifest_json)
            .map_err(|error: serde_json::Error| PgError::Import(error.to_string()))?;
        let parsed_object_id: proof_domain::ObjectId = object_id
            .parse::<proof_domain::ObjectId>()
            .map_err(|error: proof_domain::IdentifierError| PgError::Import(error.to_string()))?;
        let parsed_locale: proof_application::LocaleId = locale
            .parse()
            .map_err(|_| PgError::Import("invalid source locale".to_owned()))?;
        let raw_revision: u32 = u32::try_from(
            manifest
                .get("revision")
                .and_then(Value::as_u64)
                .ok_or_else(|| PgError::Import("rendition lacks revision".to_owned()))?,
        )
        .map_err(|_| PgError::Import("rendition revision overflow".to_owned()))?;
        let parsed_revision = proof_application::LocaleRevision::new(raw_revision)
            .map_err(|error| PgError::Import(error.to_string()))?;
        refs.push(proof_canonical::LocaleStateReference {
            object_id: parsed_object_id,
            locale: parsed_locale,
            revision: parsed_revision,
            rendition_digest: rendition_digest_text.parse().map_err(
                |error: proof_domain::DigestParseError| PgError::Import(error.to_string()),
            )?,
            source_object_digest: manifest
                .get("source_object_digest")
                .and_then(Value::as_str)
                .ok_or_else(|| PgError::Import("manifest lacks source digest".to_owned()))?
                .parse::<ContentDigest>()
                .map_err(|error: proof_domain::DigestParseError| {
                    PgError::Import(error.to_string())
                })?,
            schema_id: SchemaId::new(
                manifest
                    .get("schema_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| PgError::Import("manifest lacks schema id".to_owned()))?
                    .to_owned(),
            )
            .map_err(|error| PgError::Import(error.to_string()))?,
            schema_version: SchemaVersion::new(
                u32::try_from(
                    manifest
                        .get("schema_version")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| {
                            PgError::Import("manifest lacks schema version".to_owned())
                        })?,
                )
                .map_err(|_| PgError::Import("invalid schema version".to_owned()))?,
            )
            .map_err(|error| PgError::Import(error.to_string()))?,
        });
    }
    Ok(refs)
}

/// Reads the Known State predecessor reference for a v2 head.
fn read_previous_known_state(
    connection: &Connection,
    current_sequence: u64,
) -> Result<proof_canonical::PreviousKnownStateReference, PgError> {
    let (api_version, sequence, raw_digest): (String, i64, String) = connection
        .query_row(
            "SELECT api_version, authoritative_sequence, state_digest
             FROM known_state_artifacts WHERE authoritative_sequence < ?1
             ORDER BY authoritative_sequence DESC LIMIT 1",
            [i64::try_from(current_sequence)
                .map_err(|_| PgError::Import("sequence overflow".to_owned()))?],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| PgError::Import(error.to_string()))?
        .ok_or_else(|| PgError::Import("a v2 Known State lacks its predecessor".to_owned()))?;
    let parsed_digest: ContentDigest = raw_digest
        .parse()
        .map_err(|error: proof_domain::DigestParseError| PgError::Import(error.to_string()))?;
    Ok(proof_canonical::PreviousKnownStateReference {
        api_version,
        authoritative_sequence: u64::try_from(sequence)
            .map_err(|_| PgError::Import("negative predecessor sequence".to_owned()))?,
        digest: parsed_digest,
    })
}

/// Reads, re-verifies, and chain-links the local authority records.
fn read_authority_records(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<Vec<ImportedAuthorityRecord>, PgError> {
    let mut statement = connection
        .prepare(
            "SELECT authority_sequence, workspace_id, previous_authority_record_digest,
                    record_kind, record_json, record_digest
             FROM authority_records ORDER BY authority_sequence",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;

    let mut records = Vec::new();
    let mut previous_digest: Option<ContentDigest> = None;
    for (index, row) in rows.enumerate() {
        let (sequence, record_workspace_id, predecessor, record_kind, record_json, record_digest) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let expected_sequence = i64::try_from(index + 1)
            .map_err(|_| PgError::Import("authority sequence overflow".to_owned()))?;
        if sequence != expected_sequence {
            return Err(PgError::Import(
                "the source authority chain has a sequence gap or reorder".to_owned(),
            ));
        }
        if record_workspace_id != workspace_id.to_string() {
            return Err(PgError::Import(
                "an authority record belongs to a different Workspace".to_owned(),
            ));
        }
        let record_digest = record_digest
            .parse::<ContentDigest>()
            .map_err(|error| PgError::Import(format!("invalid authority digest: {error}")))?;
        verify_canonical_digest(
            record_json.as_bytes(),
            ArtifactKind::AuthorityRecordV1,
            record_digest,
            &format!("authority record {sequence}"),
        )?;
        let predecessor = predecessor
            .map(|text| text.parse::<ContentDigest>())
            .transpose()
            .map_err(|error| PgError::Import(format!("invalid predecessor digest: {error}")))?;
        if predecessor != previous_digest {
            return Err(PgError::Import(
                "the source authority predecessor digest does not link to the previous record"
                    .to_owned(),
            ));
        }
        previous_digest = Some(record_digest);
        records.push(ImportedAuthorityRecord {
            authority_sequence: sequence,
            workspace_id: record_workspace_id,
            record_digest,
            payload_type: record_kind,
            payload: record_json.into_bytes(),
            predecessor_digest: predecessor,
        });
    }
    Ok(records)
}

fn read_schema_facts(connection: &Connection) -> Result<Vec<ImportedFact>, PgError> {
    let mut statement = connection
        .prepare(
            "SELECT schema_id, schema_version, document_json, document_digest, authoritative_sequence
             FROM schema_versions ORDER BY schema_id, schema_version",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;

    let mut facts = Vec::new();
    for row in rows {
        let (schema_id, schema_version, document_json, document_digest, sequence) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let digest = document_digest
            .parse::<ContentDigest>()
            .map_err(|error| PgError::Import(format!("invalid Schema digest: {error}")))?;
        let fact_id = format!("schema/{schema_id}/{schema_version}");
        verify_canonical_digest(
            document_json.as_bytes(),
            ArtifactKind::SchemaVersionV1,
            digest,
            &fact_id,
        )?;
        facts.push(ImportedFact {
            fact_id,
            fact_kind: "schema".to_owned(),
            authority_sequence: sequence,
            fact_digest: digest,
            body: document_json.into_bytes(),
        });
    }
    Ok(facts)
}

fn read_object_facts(connection: &Connection) -> Result<Vec<ImportedFact>, PgError> {
    let mut statement = connection
        .prepare(
            "SELECT object_id, revision, schema_id, schema_version, lifecycle_state,
                    content_json, object_digest, authoritative_sequence
             FROM object_revisions ORDER BY object_id, revision",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;

    let mut facts = Vec::new();
    for row in rows {
        let (
            object_id,
            revision,
            schema_id,
            schema_version,
            lifecycle_state,
            content_json,
            object_digest,
            sequence,
        ) = row.map_err(|error| PgError::Import(error.to_string()))?;
        let expected = object_digest
            .parse::<ContentDigest>()
            .map_err(|error| PgError::Import(format!("invalid Object digest: {error}")))?;
        let fact_id = format!("object/{object_id}/{revision}");
        let manifest = object_revision_manifest(
            &object_id,
            revision,
            &schema_id,
            schema_version,
            lifecycle_state.as_str(),
            &content_json,
        )?;
        let canonical =
            canonicalize(&manifest).map_err(|error| PgError::Import(error.to_string()))?;
        let recomputed = digest(ArtifactKind::ObjectRevisionV1, &canonical);
        if recomputed != expected {
            return Err(PgError::Import(format!(
                "{fact_id}: Object digest does not reproduce"
            )));
        }
        facts.push(ImportedFact {
            fact_id,
            fact_kind: "object".to_owned(),
            authority_sequence: sequence,
            fact_digest: expected,
            body: canonical.as_bytes().to_vec(),
        });
    }
    Ok(facts)
}

fn read_rendition_facts(connection: &Connection) -> Result<Vec<ImportedFact>, PgError> {
    let mut statement = connection
        .prepare(
            "SELECT object_id, locale, revision, manifest_json, rendition_digest, authoritative_sequence
             FROM object_locale_revisions ORDER BY object_id, locale, revision",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;

    let mut facts = Vec::new();
    for row in rows {
        let (object_id, locale, revision, manifest_json, rendition_digest, sequence) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let digest = rendition_digest
            .parse::<ContentDigest>()
            .map_err(|error| PgError::Import(format!("invalid rendition digest: {error}")))?;
        let fact_id = format!("rendition/{object_id}/{locale}/{revision}");
        verify_canonical_digest(
            manifest_json.as_bytes(),
            ArtifactKind::ObjectLocaleRevisionV1,
            digest,
            &fact_id,
        )?;
        facts.push(ImportedFact {
            fact_id,
            fact_kind: "rendition".to_owned(),
            authority_sequence: sequence,
            fact_digest: digest,
            body: manifest_json.into_bytes(),
        });
    }
    Ok(facts)
}

fn read_release_facts(connection: &Connection) -> Result<Vec<ImportedFact>, PgError> {
    let mut statement = connection
        .prepare(
            "SELECT release_id, release_sequence, manifest_json, release_digest, api_version
             FROM releases ORDER BY release_sequence",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;

    let mut facts = Vec::new();
    for row in rows {
        let (release_id, release_sequence, manifest_json, release_digest, api_version) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let digest = release_digest
            .parse::<ContentDigest>()
            .map_err(|error| PgError::Import(format!("invalid Release digest: {error}")))?;
        let (fact_kind, artifact_kind) = match api_version.as_str() {
            "proof.dev/release/v1" => ("release", ArtifactKind::ReleaseV1),
            "proof.dev/release/v2" => ("release_v2", ArtifactKind::ReleaseV2),
            other => {
                return Err(PgError::Import(format!(
                    "unsupported Release api version `{other}`"
                )));
            }
        };
        let fact_id = format!("release/{release_id}");
        verify_canonical_digest(manifest_json.as_bytes(), artifact_kind, digest, &fact_id)?;
        facts.push(ImportedFact {
            fact_id,
            fact_kind: fact_kind.to_owned(),
            authority_sequence: release_sequence,
            fact_digest: digest,
            body: manifest_json.into_bytes(),
        });
    }
    Ok(facts)
}

/// Reconstructs the canonical `ObjectRevisionV1` manifest for one source Object.
#[allow(clippy::too_many_arguments)]
fn object_revision_manifest(
    object_id: &str,
    revision: i64,
    schema_id: &str,
    schema_version: i64,
    lifecycle_state: &str,
    content_json: &str,
) -> Result<Value, PgError> {
    if revision != 1 || lifecycle_state != "active" {
        return Err(PgError::Import(
            "source Object revision or lifecycle state is unsupported".to_owned(),
        ));
    }
    let content: Value = serde_json::from_str(content_json)
        .map_err(|error| PgError::Import(format!("invalid Object content JSON: {error}")))?;
    Ok(serde_json::json!({
        "api_version": "proof.dev/object-revision/v1",
        "content": content,
        "lifecycle_state": "active",
        "object_id": object_id,
        "relationships": [],
        "revision": 1,
        "schema_id": schema_id,
        "schema_version": schema_version,
    }))
}

/// Inserts the singleton Workspace write head row carrying the source heads.
fn insert_workspace_head(
    transaction: &mut postgres::Transaction<'_>,
    source: &VerifiedSource,
) -> Result<(), PgError> {
    let migration = transaction
        .query_opt(
            "SELECT version, phase FROM migration_head WHERE singleton = 1",
            &[],
        )
        .map_err(|error| PgError::Import(error.to_string()))?
        .ok_or_else(|| PgError::Import("migration head is absent during import".to_owned()))?;
    let migration_version: i32 = migration.get(0);
    let migration_phase: String = migration.get(1);
    if migration_phase != "verified" {
        return Err(PgError::Import(format!(
            "migration head is in phase `{migration_phase}` during import"
        )));
    }

    let release_head = source
        .facts
        .iter()
        .filter(|fact| fact.fact_kind == "release" || fact.fact_kind == "release_v2")
        .max_by_key(|fact| fact.authority_sequence)
        .map(|fact| fact.fact_digest.to_string());

    let authority_head_sequence = i64::try_from(source.authority_head.sequence)
        .map_err(|_| PgError::Import("authority head sequence exceeds BIGINT range".to_owned()))?;
    let authoritative_sequence = i64::try_from(source.authoritative_sequence)
        .map_err(|_| PgError::Import("authoritative sequence exceeds BIGINT range".to_owned()))?;
    let release_sequence = i64::try_from(source.release_sequence)
        .map_err(|_| PgError::Import("release sequence exceeds BIGINT range".to_owned()))?;

    transaction
        .execute(
            "INSERT INTO workspace_write_head (
                 singleton, workspace_id, migration_version, transaction_sequence,
                 authority_sequence, content_sequence, release_sequence,
                 authority_head_digest, authority_head_sequence, content_head_digest,
                 release_head_digest, policy_head_digest, configuration_head_digest
             ) VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL, NULL)",
            &[
                &source.workspace_id.to_string(),
                &migration_version,
                &authority_head_sequence,
                &authority_head_sequence,
                &authoritative_sequence,
                &release_sequence,
                &source.authority_head.record_digest.to_string(),
                &authority_head_sequence,
                &source.state_digest.to_string(),
                &release_head,
            ],
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    Ok(())
}

/// Inserts every verified local authority record.
fn insert_authority_records(
    transaction: &mut postgres::Transaction<'_>,
    source: &VerifiedSource,
) -> Result<(), PgError> {
    for record in &source.authority_records {
        transaction
            .execute(
                "INSERT INTO authority_records (
                     authority_sequence, workspace_id, record_digest, payload_type, payload,
                     predecessor_digest, committed_at
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &record.authority_sequence,
                    &record.workspace_id.as_str(),
                    &record.record_digest.to_string(),
                    &record.payload_type.as_str(),
                    &record.payload,
                    &record.predecessor_digest.map(|digest| digest.to_string()),
                    &SystemTime::now(),
                ],
            )
            .map_err(|error| PgError::Import(error.to_string()))?;
    }
    Ok(())
}

/// Inserts every verified canonical fact.
fn insert_facts(
    transaction: &mut postgres::Transaction<'_>,
    source: &VerifiedSource,
) -> Result<(), PgError> {
    for fact in &source.facts {
        transaction
            .execute(
                "INSERT INTO facts (
                     fact_id, workspace_id, fact_kind, authority_sequence, fact_digest,
                     body, committed_at
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &fact.fact_id.as_str(),
                    &source.workspace_id.to_string(),
                    &fact.fact_kind.as_str(),
                    &fact.authority_sequence,
                    &fact.fact_digest.to_string(),
                    &fact.body,
                    &SystemTime::now(),
                ],
            )
            .map_err(|error| PgError::Import(error.to_string()))?;
    }
    Ok(())
}
