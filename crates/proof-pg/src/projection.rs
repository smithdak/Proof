//! Projection rebuild and atomic generation swap (contract §"Migration and
//! projection rebuild").

use std::{error::Error, time::SystemTime};

use postgres::{Client, GenericClient, IsolationLevel, Transaction};
use proof_application::{
    LocalizedContentError, OBJECT_LIST_STATE_SCOPE, ObjectListCommand, ObjectListEntry,
    ObjectListResult, ObjectRenditionHead, SchemaGetCommand, SchemaGetResult, SchemaListCommand,
    SchemaListEntry, SchemaListResult, SchemaReadProvenance,
};
use proof_canonical::{
    ObjectStateReference, canonicalize, digest, known_state_digest_with_objects, parse_strict,
};
use proof_domain::{ArtifactKind, ContentDigest, SchemaId, SchemaVersion, WorkspaceId};
use proof_remote::{
    ActiveAuthorityKeyResolver, AuthorityHeadV1, RemoteError, VerifiedRemoteAuthorityRecord,
    derive_key_digest, parse_remote_authority_record_envelope, validate_chain,
    verify_remote_authority_record_envelope,
};
use serde_json::Value;

use crate::{PgError, transaction::WorkspaceHeadSnapshot};

/// One verified projection generation (contract §"Migration and projection
/// rebuild").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionGeneration {
    /// Monotonic generation number.
    pub generation: u64,
    /// Exact heads captured at rebuild time.
    pub heads: WorkspaceHeadSnapshot,
    /// Per-kind derived-row counts.
    pub counts: ProjectionCounts,
    /// Domain-separated digest of the complete derived state.
    pub state_digest: ContentDigest,
}

/// Per-kind derived-row counts captured by a rebuild (contract §"Migration and
/// projection rebuild").
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProjectionCounts {
    /// Derived Object count.
    pub objects: u64,
    /// Derived exact-locale rendition count.
    pub renditions: u64,
    /// Derived Schema count.
    pub schemas: u64,
    /// Derived Release count.
    pub releases: u64,
}

/// A read-side pin that keeps one retired generation readable (contract
/// §"Migration and projection rebuild").
///
/// A read transaction pins exactly one projection generation for its lifetime.
/// A retired generation remains readable until no transaction still holds that
/// pin; only then may a separately qualified garbage collector remove it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetiredGenerationPin {
    /// The pinned generation number.
    pub generation: u64,
}

/// The four derived projection tables materialized by every rebuild. They are
/// deliberately distinct from the append-only `facts` table (contract
/// §"Migration and projection rebuild"): rebuild writes only these tables and
/// the `projection_generations` pointer, never the facts, authority records,
/// idempotency, artifact catalog, outbox, attempt, or receipt tables.
pub const DERIVED_TABLES_DDL: [&str; 4] = [
    PROJECTION_SCHEMAS_DDL,
    PROJECTION_OBJECTS_DDL,
    PROJECTION_RENDITIONS_DDL,
    PROJECTION_RELEASES_DDL,
];

/// Derived Schema projection (identity, version, digest, causal sequence).
const PROJECTION_SCHEMAS_DDL: &str = "CREATE TABLE IF NOT EXISTS projection_schemas (
    generation BIGINT NOT NULL,
    schema_id TEXT NOT NULL,
    schema_version BIGINT NOT NULL,
    document_digest TEXT NOT NULL,
    authority_sequence BIGINT NOT NULL,
    PRIMARY KEY (generation, schema_id, schema_version)
);";

/// Derived Object projection.
const PROJECTION_OBJECTS_DDL: &str = "CREATE TABLE IF NOT EXISTS projection_objects (
    generation BIGINT NOT NULL,
    object_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    schema_id TEXT NOT NULL,
    schema_version BIGINT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    object_digest TEXT NOT NULL,
    authority_sequence BIGINT NOT NULL,
    PRIMARY KEY (generation, object_id, revision)
);";

/// Derived exact-locale rendition projection.
const PROJECTION_RENDITIONS_DDL: &str = "CREATE TABLE IF NOT EXISTS projection_renditions (
    generation BIGINT NOT NULL,
    object_id TEXT NOT NULL,
    locale TEXT NOT NULL,
    revision BIGINT NOT NULL,
    rendition_digest TEXT NOT NULL,
    source_object_digest TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    schema_version BIGINT NOT NULL,
    authority_sequence BIGINT NOT NULL,
    PRIMARY KEY (generation, object_id, locale, revision)
);";

/// Derived Release projection.
const PROJECTION_RELEASES_DDL: &str = "CREATE TABLE IF NOT EXISTS projection_releases (
    generation BIGINT NOT NULL,
    release_id TEXT NOT NULL,
    release_sequence BIGINT NOT NULL,
    release_digest TEXT NOT NULL,
    PRIMARY KEY (generation, release_id)
);";

/// Fact kind marker for a Schema canonical fact.
const FACT_KIND_SCHEMA: &str = "schema";
/// Fact kind marker for an Object canonical fact.
const FACT_KIND_OBJECT: &str = "object";
/// Fact kind marker for an exact-locale rendition canonical fact.
const FACT_KIND_RENDITION: &str = "rendition";
/// Fact kind marker for a Release canonical fact.
const FACT_KIND_RELEASE: &str = "release";

#[derive(Clone)]
struct ProjectedSchemaRow {
    schema_id: SchemaId,
    schema_version: SchemaVersion,
    document_digest: ContentDigest,
    authoritative_sequence: u64,
}

#[derive(Clone)]
struct ProjectedObjectRow {
    object_id: proof_domain::ObjectId,
    revision: proof_domain::ObjectRevision,
    schema_id: SchemaId,
    schema_version: SchemaVersion,
    object_digest: ContentDigest,
    authoritative_sequence: u64,
}

struct StoredFact {
    authority_sequence: i64,
    fact_digest: ContentDigest,
    body: Vec<u8>,
}

/// Reads one exact Schema through the active generation and reverified facts.
///
/// # Errors
///
/// Returns [`LocalizedContentError::NotFound`] for an absent exact tuple and
/// fails closed on projection/fact drift or storage failure.
pub fn get_schema<C: GenericClient>(
    client: &mut C,
    workspace_id: WorkspaceId,
    command: &SchemaGetCommand,
) -> Result<SchemaGetResult, LocalizedContentError> {
    let generation = read_active_generation(client)?;
    let row = client
        .query_opt(
            "SELECT schema_id, schema_version, document_digest, authority_sequence
             FROM projection_schemas
             WHERE generation = $1 AND schema_id = $2 AND schema_version = $3",
            &[
                &generation,
                &command.schema_id.as_str(),
                &i64::from(command.schema_version.get()),
            ],
        )
        .map_err(read_storage)?
        .ok_or(LocalizedContentError::NotFound)?;
    let projected = projected_schema_row(&row)?;
    let (entry, document) = verified_schema_projection(client, workspace_id, projected)?;
    Ok(SchemaGetResult {
        schema_id: entry.schema_id,
        schema_version: entry.schema_version,
        document,
        document_digest: entry.document_digest,
        provenance: entry.provenance,
    })
}

/// Reads one bounded Schema page through the active generation and reverified facts.
///
/// # Errors
///
/// Returns a typed input, storage, or integrity error without broadening the
/// requested Workspace or Schema filter.
pub fn list_schemas<C: GenericClient>(
    client: &mut C,
    workspace_id: WorkspaceId,
    command: &SchemaListCommand,
) -> Result<SchemaListResult, LocalizedContentError> {
    let (cursor, page_size) = command.validated_bounds()?;
    let cursor = i64::try_from(cursor).map_err(|_| LocalizedContentError::InvalidInput)?;
    let generation = read_active_generation(client)?;
    let schema_filter = command.schema_id.as_ref().map(SchemaId::as_str);
    let rows = client
        .query(
            "SELECT schema_id, schema_version, document_digest, authority_sequence
             FROM projection_schemas
             WHERE generation = $1
               AND authority_sequence > $2
               AND ($3::TEXT IS NULL OR schema_id = $3)
             ORDER BY authority_sequence ASC
             LIMIT $4",
            &[
                &generation,
                &cursor,
                &schema_filter,
                &(i64::from(page_size) + 1),
            ],
        )
        .map_err(read_storage)?;
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let projected = projected_schema_row(&row)?;
        let (entry, _) = verified_schema_projection(client, workspace_id, projected)?;
        entries.push(entry);
    }
    let has_more = entries.len() > usize::try_from(page_size).unwrap_or(usize::MAX);
    if has_more {
        entries.pop();
    }
    let next_cursor = has_more.then(|| {
        entries
            .last()
            .expect("a page with an extra row has a returned row")
            .provenance
            .authoritative_sequence
            .to_string()
    });
    Ok(SchemaListResult {
        entries,
        next_cursor,
    })
}

/// Reads one bounded committed Object page through the active generation and
/// reverified facts.
///
/// # Errors
///
/// Returns a typed input, not-found, storage, or integrity error. Release
/// coverage is always bound to the requested Environment's current Release
/// Edition sequence.
#[allow(clippy::too_many_lines)]
pub fn list_objects<C: GenericClient>(
    client: &mut C,
    workspace_id: WorkspaceId,
    command: &ObjectListCommand,
) -> Result<ObjectListResult, LocalizedContentError> {
    let (cursor, page_size) = command.validated_bounds()?;
    let cursor = i64::try_from(cursor).map_err(|_| LocalizedContentError::InvalidInput)?;
    let generation = read_active_generation(client)?;
    let release_sequence = current_release_state_sequence(
        client,
        workspace_id,
        generation,
        command.environment_id.as_str(),
    )?;
    let schema_filter = command.schema_id.as_ref().map(SchemaId::as_str);
    let locale_filter = command.locale.as_ref().map(proof_domain::LocaleId::as_str);
    let object_ids = command
        .object_ids
        .as_ref()
        .map(|ids| ids.iter().map(ToString::to_string).collect::<Vec<_>>())
        .unwrap_or_default();
    let ignore_object_ids = command.object_ids.is_none();
    let rows = client
        .query(
            "WITH object_heads AS (
                 SELECT object_id, revision, schema_id, schema_version, lifecycle_state,
                        object_digest, authority_sequence,
                        ROW_NUMBER() OVER (
                            PARTITION BY object_id ORDER BY revision DESC
                        ) AS head_rank
                 FROM projection_objects
                 WHERE generation = $1
             )
             SELECT object_id, revision, schema_id, schema_version, lifecycle_state,
                    object_digest, authority_sequence
             FROM object_heads AS object
             WHERE object.head_rank = 1
               AND object.authority_sequence > $2
               AND ($3::TEXT IS NULL OR object.schema_id = $3)
               AND ($4::TEXT IS NULL OR EXISTS (
                   SELECT 1 FROM projection_renditions AS rendition
                   WHERE rendition.generation = $1
                     AND rendition.object_id = object.object_id
                     AND rendition.locale = $4
                     AND rendition.revision = (
                         SELECT MAX(inner_rendition.revision)
                         FROM projection_renditions AS inner_rendition
                         WHERE inner_rendition.generation = $1
                           AND inner_rendition.object_id = rendition.object_id
                           AND inner_rendition.locale = rendition.locale
                     )
               ))
               AND ($5 OR object.object_id = ANY($6))
             ORDER BY object.authority_sequence ASC
             LIMIT $7",
            &[
                &generation,
                &cursor,
                &schema_filter,
                &locale_filter,
                &ignore_object_ids,
                &object_ids,
                &(i64::from(page_size) + 1),
            ],
        )
        .map_err(read_storage)?;
    let mut objects = Vec::with_capacity(rows.len());
    for row in rows {
        let object = projected_object_row(&row)?;
        verify_object_projection(client, workspace_id, &object)?;
        objects.push(object);
    }
    let has_more = objects.len() > usize::try_from(page_size).unwrap_or(usize::MAX);
    if has_more {
        objects.pop();
    }
    let next_cursor = has_more.then(|| {
        objects
            .last()
            .expect("a page with an extra row has a returned row")
            .authoritative_sequence
            .to_string()
    });
    let mut entries = Vec::with_capacity(objects.len());
    for object in objects {
        let released_revision = released_object_revision(
            client,
            workspace_id,
            generation,
            object.object_id,
            release_sequence,
        )?;
        let head_renditions = object_rendition_heads(
            client,
            workspace_id,
            generation,
            object.object_id,
            command.locale.as_ref(),
        )?;
        entries.push(ObjectListEntry {
            object_id: object.object_id,
            schema_id: object.schema_id,
            schema_version: object.schema_version,
            covered_by_current_release: released_revision == Some(object.revision),
            released_revision,
            head_renditions,
        });
    }
    Ok(ObjectListResult {
        state_scope: OBJECT_LIST_STATE_SCOPE.to_owned(),
        entries,
        next_cursor,
    })
}

fn read_active_generation<C: GenericClient>(client: &mut C) -> Result<i64, LocalizedContentError> {
    let rows = client
        .query(
            "SELECT generation FROM projection_generations WHERE active = TRUE",
            &[],
        )
        .map_err(read_storage)?;
    if rows.len() != 1 {
        return Err(read_integrity(
            "the active projection generation is not unique",
        ));
    }
    Ok(rows[0].get(0))
}

fn projected_schema_row(row: &postgres::Row) -> Result<ProjectedSchemaRow, LocalizedContentError> {
    let raw_version: i64 = row.get(1);
    let raw_sequence: i64 = row.get(3);
    Ok(ProjectedSchemaRow {
        schema_id: SchemaId::new(row.get::<_, String>(0)).map_err(read_integrity_error)?,
        schema_version: SchemaVersion::new(
            u32::try_from(raw_version).map_err(|_| read_integrity("invalid Schema version"))?,
        )
        .map_err(read_integrity_error)?,
        document_digest: row
            .get::<_, String>(2)
            .parse()
            .map_err(read_integrity_error)?,
        authoritative_sequence: u64::try_from(raw_sequence)
            .map_err(|_| read_integrity("invalid Schema sequence"))?,
    })
}

fn verified_schema_projection<C: GenericClient>(
    client: &mut C,
    workspace_id: WorkspaceId,
    projected: ProjectedSchemaRow,
) -> Result<(SchemaListEntry, Value), LocalizedContentError> {
    let fact_id = format!(
        "schema/{}/{}",
        projected.schema_id.as_str(),
        projected.schema_version.get()
    );
    let fact = required_fact(client, &fact_id, workspace_id, FACT_KIND_SCHEMA)?;
    if fact.authority_sequence
        != i64::try_from(projected.authoritative_sequence)
            .map_err(|_| read_integrity("invalid Schema sequence"))?
        || fact.fact_digest != projected.document_digest
    {
        return Err(read_integrity("Schema projection and fact differ"));
    }
    let document = verify_canonical_digest(
        &fact.body,
        ArtifactKind::SchemaVersionV1,
        fact.fact_digest,
        &fact_id,
    )
    .map_err(read_projection_error)?;
    if !document.is_object() {
        return Err(read_integrity("Schema document is not an object"));
    }
    let sidecar_id = format!(
        "localizable_schema/{}/{}",
        projected.schema_id.as_str(),
        projected.schema_version.get()
    );
    let sidecar = required_derived_fact(
        client,
        &sidecar_id,
        workspace_id,
        "localizable_schema",
        "proof:parity:localizable-schema:v1",
    )?;
    if sidecar.get("api_version").and_then(Value::as_str)
        != Some("proof.dev/parity/localizable-schema/v1")
        || sidecar.get("schema_id").and_then(Value::as_str) != Some(projected.schema_id.as_str())
        || sidecar.get("schema_version").and_then(Value::as_u64)
            != Some(u64::from(projected.schema_version.get()))
        || sidecar.get("document_digest").and_then(Value::as_str)
            != Some(projected.document_digest.to_string().as_str())
        || sidecar.get("document") != Some(&document)
        || sidecar
            .get("authoritative_sequence")
            .and_then(Value::as_u64)
            != Some(projected.authoritative_sequence)
    {
        return Err(read_integrity(
            "Schema provenance fact does not match projection",
        ));
    }
    let changeset_id = sidecar
        .get("changeset_id")
        .and_then(Value::as_str)
        .ok_or_else(|| read_integrity("Schema provenance lacks changeset_id"))?
        .parse()
        .map_err(read_integrity_error)?;
    let edit_id = sidecar
        .get("edit_id")
        .and_then(Value::as_str)
        .ok_or_else(|| read_integrity("Schema provenance lacks edit_id"))?
        .parse()
        .map_err(read_integrity_error)?;
    Ok((
        SchemaListEntry {
            schema_id: projected.schema_id,
            schema_version: projected.schema_version,
            document_digest: projected.document_digest,
            provenance: SchemaReadProvenance {
                changeset_id,
                edit_id,
                authoritative_sequence: projected.authoritative_sequence,
            },
        },
        document,
    ))
}

fn projected_object_row(row: &postgres::Row) -> Result<ProjectedObjectRow, LocalizedContentError> {
    let raw_revision: i64 = row.get(1);
    let raw_schema_version: i64 = row.get(3);
    let lifecycle_state: String = row.get(4);
    let raw_sequence: i64 = row.get(6);
    if lifecycle_state != "active" {
        return Err(read_integrity("unsupported Object lifecycle state"));
    }
    Ok(ProjectedObjectRow {
        object_id: row
            .get::<_, String>(0)
            .parse()
            .map_err(read_integrity_error)?,
        revision: proof_domain::ObjectRevision::new(
            u32::try_from(raw_revision).map_err(|_| read_integrity("invalid Object revision"))?,
        )
        .map_err(read_integrity_error)?,
        schema_id: SchemaId::new(row.get::<_, String>(2)).map_err(read_integrity_error)?,
        schema_version: SchemaVersion::new(
            u32::try_from(raw_schema_version)
                .map_err(|_| read_integrity("invalid Schema version"))?,
        )
        .map_err(read_integrity_error)?,
        object_digest: row
            .get::<_, String>(5)
            .parse()
            .map_err(read_integrity_error)?,
        authoritative_sequence: u64::try_from(raw_sequence)
            .map_err(|_| read_integrity("invalid Object sequence"))?,
    })
}

fn verify_object_projection<C: GenericClient>(
    client: &mut C,
    workspace_id: WorkspaceId,
    projected: &ProjectedObjectRow,
) -> Result<(), LocalizedContentError> {
    let fact_id = format!(
        "object/{}/{}",
        projected.object_id,
        projected.revision.get()
    );
    let fact = required_fact(client, &fact_id, workspace_id, FACT_KIND_OBJECT)?;
    if fact.authority_sequence
        != i64::try_from(projected.authoritative_sequence)
            .map_err(|_| read_integrity("invalid Object sequence"))?
        || fact.fact_digest != projected.object_digest
    {
        return Err(read_integrity("Object projection and fact differ"));
    }
    let body = verify_canonical_digest(
        &fact.body,
        ArtifactKind::ObjectRevisionV1,
        fact.fact_digest,
        &fact_id,
    )
    .map_err(read_projection_error)?;
    let reference = parse_object_fact(&body, fact.fact_digest).map_err(read_projection_error)?;
    if reference.object_id != projected.object_id
        || reference.revision != projected.revision
        || reference.schema_id != projected.schema_id
        || reference.schema_version != projected.schema_version
        || reference.object_digest != projected.object_digest
    {
        return Err(read_integrity("Object fact does not match projection"));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn current_release_state_sequence<C: GenericClient>(
    client: &mut C,
    workspace_id: WorkspaceId,
    generation: i64,
    environment_id: &str,
) -> Result<u64, LocalizedContentError> {
    let pointer_id = format!("environment_current/{environment_id}");
    let pointer = optional_derived_fact(
        client,
        &pointer_id,
        workspace_id,
        "environment_current",
        "proof:parity:environment-current:v1",
    )?
    .ok_or(LocalizedContentError::NotFound)?;
    if pointer.get("api_version").and_then(Value::as_str)
        != Some("proof.dev/parity/environment-current/v1")
        || pointer.get("environment_id").and_then(Value::as_str) != Some(environment_id)
    {
        return Err(read_integrity(
            "Environment current-Release fact is malformed",
        ));
    }
    let release_id = pointer
        .get("release_id")
        .and_then(Value::as_str)
        .ok_or_else(|| read_integrity("Environment pointer lacks release_id"))?;
    let projected_release = client
        .query_opt(
            "SELECT release_sequence, release_digest FROM projection_releases
             WHERE generation = $1 AND release_id = $2",
            &[&generation, &release_id],
        )
        .map_err(read_storage)?
        .ok_or_else(|| read_integrity("current Release is absent from active projection"))?;
    let release_sequence: i64 = projected_release.get(0);
    let release_digest: ContentDigest = projected_release
        .get::<_, String>(1)
        .parse()
        .map_err(read_integrity_error)?;
    if pointer.get("release_sequence").and_then(Value::as_u64)
        != u64::try_from(release_sequence).ok()
    {
        return Err(read_integrity(
            "Environment pointer Release sequence differs",
        ));
    }
    let release_meta = required_derived_fact(
        client,
        &format!("release_meta/{release_id}"),
        workspace_id,
        "release_meta",
        "proof:parity:release-metadata:v1",
    )?;
    if release_meta.get("release_id").and_then(Value::as_str) != Some(release_id)
        || release_meta.get("release_digest").and_then(Value::as_str)
            != Some(release_digest.to_string().as_str())
    {
        return Err(read_integrity(
            "Release metadata differs from active projection",
        ));
    }
    let release_api_version = release_meta
        .get("release_api_version")
        .and_then(Value::as_str)
        .ok_or_else(|| read_integrity("Release metadata lacks API version"))?;
    let release_fact = required_fact(
        client,
        &format!("release/{release_id}"),
        workspace_id,
        release_fact_kind(release_api_version)?,
    )?;
    let release_artifact_kind = match release_api_version {
        proof_application::RELEASE_V1_API_VERSION => ArtifactKind::ReleaseV1,
        proof_application::LOCALIZED_RELEASE_API_VERSION => ArtifactKind::ReleaseV2,
        _ => return Err(LocalizedContentError::UnsupportedVersion),
    };
    if release_fact.fact_digest != release_digest
        || release_fact.authority_sequence != release_sequence
    {
        return Err(read_integrity(
            "Release fact differs from active projection",
        ));
    }
    let release_body = verify_canonical_digest(
        &release_fact.body,
        release_artifact_kind,
        release_digest,
        release_id,
    )
    .map_err(read_projection_error)?;
    let (fact_release_id, fact_release_sequence) =
        parse_release_fact(&release_body).map_err(read_projection_error)?;
    if fact_release_id != release_id
        || fact_release_sequence != u64::try_from(release_sequence).unwrap_or(u64::MAX)
    {
        return Err(read_integrity("Release fact identity or sequence differs"));
    }
    let edition_id = release_meta
        .get("edition_id")
        .and_then(Value::as_str)
        .ok_or_else(|| read_integrity("Release metadata lacks edition_id"))?;
    let edition_meta = required_derived_fact(
        client,
        &format!("edition_meta/{edition_id}"),
        workspace_id,
        "edition_meta",
        "proof:parity:edition-metadata:v1",
    )?;
    if edition_meta.get("edition_id").and_then(Value::as_str) != Some(edition_id)
        || edition_meta.get("edition_digest").and_then(Value::as_str)
            != release_meta.get("edition_digest").and_then(Value::as_str)
    {
        return Err(read_integrity("Release and Edition metadata differ"));
    }
    edition_meta
        .get("authoritative_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| read_integrity("Edition metadata lacks state sequence"))
}

fn release_fact_kind(api_version: &str) -> Result<&'static str, LocalizedContentError> {
    match api_version {
        proof_application::RELEASE_V1_API_VERSION => Ok(FACT_KIND_RELEASE),
        proof_application::LOCALIZED_RELEASE_API_VERSION => Ok("release_v2"),
        _ => Err(LocalizedContentError::UnsupportedVersion),
    }
}

fn released_object_revision<C: GenericClient>(
    client: &mut C,
    workspace_id: WorkspaceId,
    generation: i64,
    object_id: proof_domain::ObjectId,
    release_sequence: u64,
) -> Result<Option<proof_domain::ObjectRevision>, LocalizedContentError> {
    let release_sequence = i64::try_from(release_sequence)
        .map_err(|_| read_integrity("release state sequence exceeds BIGINT"))?;
    let row = client
        .query_opt(
            "SELECT object_id, revision, schema_id, schema_version, lifecycle_state,
                    object_digest, authority_sequence
             FROM projection_objects
             WHERE generation = $1 AND object_id = $2 AND authority_sequence <= $3
             ORDER BY revision DESC LIMIT 1",
            &[&generation, &object_id.to_string(), &release_sequence],
        )
        .map_err(read_storage)?;
    row.map(|row| {
        let projected = projected_object_row(&row)?;
        verify_object_projection(client, workspace_id, &projected)?;
        Ok(projected.revision)
    })
    .transpose()
}

fn object_rendition_heads<C: GenericClient>(
    client: &mut C,
    workspace_id: WorkspaceId,
    generation: i64,
    object_id: proof_domain::ObjectId,
    locale: Option<&proof_domain::LocaleId>,
) -> Result<Vec<ObjectRenditionHead>, LocalizedContentError> {
    let locale_filter = locale.map(proof_domain::LocaleId::as_str);
    let rows = client
        .query(
            "SELECT rendition.locale, rendition.revision, rendition.rendition_digest,
                    rendition.source_object_digest, rendition.schema_id,
                    rendition.schema_version, rendition.authority_sequence
             FROM projection_renditions AS rendition
             WHERE rendition.generation = $1
               AND rendition.object_id = $2
               AND ($3::TEXT IS NULL OR rendition.locale = $3)
               AND rendition.revision = (
                   SELECT MAX(inner_rendition.revision)
                   FROM projection_renditions AS inner_rendition
                   WHERE inner_rendition.generation = $1
                     AND inner_rendition.object_id = rendition.object_id
                     AND inner_rendition.locale = rendition.locale
               )
             ORDER BY rendition.locale ASC",
            &[&generation, &object_id.to_string(), &locale_filter],
        )
        .map_err(read_storage)?;
    let mut heads = Vec::with_capacity(rows.len());
    for row in rows {
        let locale: proof_domain::LocaleId = row
            .get::<_, String>(0)
            .parse()
            .map_err(read_integrity_error)?;
        let revision = proof_domain::LocaleRevision::new(
            u32::try_from(row.get::<_, i64>(1))
                .map_err(|_| read_integrity("invalid rendition revision"))?,
        )
        .map_err(read_integrity_error)?;
        let rendition_digest: ContentDigest = row
            .get::<_, String>(2)
            .parse()
            .map_err(read_integrity_error)?;
        let source_object_digest: ContentDigest = row
            .get::<_, String>(3)
            .parse()
            .map_err(read_integrity_error)?;
        let schema_id = SchemaId::new(row.get::<_, String>(4)).map_err(read_integrity_error)?;
        let schema_version = SchemaVersion::new(
            u32::try_from(row.get::<_, i64>(5))
                .map_err(|_| read_integrity("invalid rendition Schema version"))?,
        )
        .map_err(read_integrity_error)?;
        let sequence = row.get::<_, i64>(6);
        let fact_id = format!(
            "rendition/{object_id}/{}/{revision}",
            locale.as_str(),
            revision = revision.get()
        );
        let fact = required_fact(client, &fact_id, workspace_id, FACT_KIND_RENDITION)?;
        if fact.authority_sequence != sequence || fact.fact_digest != rendition_digest {
            return Err(read_integrity("rendition projection and fact differ"));
        }
        let body = verify_canonical_digest(
            &fact.body,
            ArtifactKind::ObjectLocaleRevisionV1,
            rendition_digest,
            &fact_id,
        )
        .map_err(read_projection_error)?;
        let parsed =
            parse_rendition_fact(&body, rendition_digest).map_err(read_projection_error)?;
        if parsed.object_id != object_id
            || parsed.locale != locale
            || parsed.revision != revision
            || parsed.rendition_digest != rendition_digest
            || parsed.source_object_digest != source_object_digest
            || parsed.schema_id != schema_id
            || parsed.schema_version != schema_version
        {
            return Err(read_integrity("rendition fact does not match projection"));
        }
        heads.push(ObjectRenditionHead {
            locale,
            revision,
            rendition_digest,
        });
    }
    Ok(heads)
}

fn required_fact<C: GenericClient>(
    client: &mut C,
    fact_id: &str,
    workspace_id: WorkspaceId,
    fact_kind: &str,
) -> Result<StoredFact, LocalizedContentError> {
    let row = client
        .query_opt(
            "SELECT authority_sequence, fact_digest, body FROM facts
             WHERE fact_id = $1 AND workspace_id = $2 AND fact_kind = $3",
            &[&fact_id, &workspace_id.to_string(), &fact_kind],
        )
        .map_err(read_storage)?
        .ok_or_else(|| read_integrity("active projection lacks its authoritative fact"))?;
    Ok(StoredFact {
        authority_sequence: row.get(0),
        fact_digest: row
            .get::<_, String>(1)
            .parse()
            .map_err(read_integrity_error)?,
        body: row.get(2),
    })
}

fn required_derived_fact<C: GenericClient>(
    client: &mut C,
    fact_id: &str,
    workspace_id: WorkspaceId,
    fact_kind: &str,
    digest_context: &str,
) -> Result<Value, LocalizedContentError> {
    optional_derived_fact(client, fact_id, workspace_id, fact_kind, digest_context)?
        .ok_or_else(|| read_integrity("required authoritative metadata fact is absent"))
}

fn optional_derived_fact<C: GenericClient>(
    client: &mut C,
    fact_id: &str,
    workspace_id: WorkspaceId,
    fact_kind: &str,
    digest_context: &str,
) -> Result<Option<Value>, LocalizedContentError> {
    let row = client
        .query_opt(
            "SELECT fact_digest, body FROM facts
             WHERE fact_id = $1 AND workspace_id = $2 AND fact_kind = $3",
            &[&fact_id, &workspace_id.to_string(), &fact_kind],
        )
        .map_err(read_storage)?;
    row.map(|row| {
        let digest: ContentDigest = row
            .get::<_, String>(0)
            .parse()
            .map_err(read_integrity_error)?;
        let body: Vec<u8> = row.get(1);
        let value = parse_strict(&body).map_err(read_integrity_error)?;
        let canonical = canonicalize(&value).map_err(read_integrity_error)?;
        if canonical.as_bytes() != body
            || derive_key_digest(digest_context, canonical.as_bytes()) != digest
        {
            return Err(read_integrity(
                "authoritative metadata fact does not reproduce",
            ));
        }
        Ok(value)
    })
    .transpose()
}

fn read_storage(error: impl std::fmt::Display) -> LocalizedContentError {
    LocalizedContentError::Storage(error.to_string())
}

fn read_integrity(detail: &str) -> LocalizedContentError {
    LocalizedContentError::Integrity(detail.to_owned())
}

fn read_integrity_error(error: impl std::fmt::Display) -> LocalizedContentError {
    LocalizedContentError::Integrity(error.to_string())
}

fn read_projection_error(error: impl std::fmt::Display) -> LocalizedContentError {
    LocalizedContentError::Integrity(error.to_string())
}

fn projection_error<E>(error: E) -> PgError
where
    E: Error + 'static,
{
    if let Some(error) = (&error as &(dyn Error + 'static)).downcast_ref::<postgres::Error>() {
        return crate::transaction::transaction_error(error);
    }
    PgError::Projection(error.to_string())
}

/// Converts a non-negative projection generation to its `BIGINT` binding form.
fn generation_bigint(generation: u64) -> Result<i64, PgError> {
    i64::try_from(generation)
        .map_err(|_| PgError::Projection("projection generation exceeds BIGINT range".to_owned()))
}

/// Ensures every derived projection table exists. Idempotent.
pub(crate) fn ensure_projection_tables(client: &mut Client) -> Result<(), PgError> {
    for ddl in DERIVED_TABLES_DDL {
        client.batch_execute(ddl).map_err(projection_error)?;
    }
    Ok(())
}

/// Rebuilds every derived row into a new generation under the Workspace head
/// lock.
///
/// The rebuild runs in a `SERIALIZABLE READ WRITE` transaction that locks the
/// single `workspace_write_head` row, verifies the authority/content/Release
/// chains, rebuilds every derived row into the next generation, and commits
/// that generation as *inactive*. The active pointer is only flipped by
/// [`atomic_swap_active_generation`], so a caller that stops after this step
/// has performed a dry run: the active generation is unchanged and no partial
/// generation is ever observable (the whole generation commits or rolls back
/// atomically).
///
/// # Errors
///
/// Returns [`PgError::Transaction`] for PostgreSQL failures and
/// [`PgError::Projection`] for validation or conversion failures.
pub fn rebuild_into_new_generation(client: &mut Client) -> Result<ProjectionGeneration, PgError> {
    ensure_projection_tables(client)?;
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .read_only(false)
        .start()
        .map_err(projection_error)?;
    let generation = rebuild_generation_in_transaction(&mut transaction)?;
    transaction.commit().map_err(projection_error)?;
    Ok(generation)
}

/// Atomically swaps the single active-generation pointer after comparing
/// identities, counts, foreign keys, versions, sequences, and state digest.
///
/// # Errors
///
/// Returns [`PgError::Transaction`] for PostgreSQL failures and
/// [`PgError::Projection`] when a generation comparison fails.
pub fn atomic_swap_active_generation(
    client: &mut Client,
    generation: &ProjectionGeneration,
) -> Result<(), PgError> {
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .read_only(false)
        .start()
        .map_err(projection_error)?;
    swap_active_generation_in_transaction(&mut transaction, generation)?;
    transaction.commit().map_err(projection_error)?;
    Ok(())
}

/// Rebuilds and atomically activates a projection generation inside a
/// caller-owned authoritative transaction. Semantic facts, authority evidence,
/// head updates, and the active projection therefore become visible together.
///
/// # Errors
///
/// Returns [`PgError::Transaction`] for PostgreSQL failures and
/// [`PgError::Projection`] for fact validation or conversion failures.
pub fn rebuild_and_swap_in_transaction(
    transaction: &mut Transaction<'_>,
) -> Result<ProjectionGeneration, PgError> {
    for ddl in DERIVED_TABLES_DDL {
        transaction.batch_execute(ddl).map_err(projection_error)?;
    }
    let generation = rebuild_generation_in_transaction(transaction)?;
    swap_active_generation_in_transaction(transaction, &generation)?;
    Ok(generation)
}

/// Rebuilds and activates the content/Release projection inside an already
/// authorized Workspace transaction. The outer UOW owns authority-chain
/// validation; this step still verifies every canonical content and Release
/// fact, exact sequences, state digest, counts, and foreign keys.
///
/// # Errors
///
/// Returns [`PgError::Transaction`] for PostgreSQL failures and
/// [`PgError::Projection`] for content validation or conversion failures.
pub fn rebuild_content_and_swap_in_transaction(
    transaction: &mut Transaction<'_>,
) -> Result<ProjectionGeneration, PgError> {
    for ddl in DERIVED_TABLES_DDL {
        transaction.batch_execute(ddl).map_err(projection_error)?;
    }
    let generation = rebuild_generation(transaction, false)?;
    swap_active_generation_in_transaction(transaction, &generation)?;
    Ok(generation)
}

/// The locked head row plus the Workspace identity needed to rebuild state.
struct HeadRow {
    workspace_id: WorkspaceId,
    snapshot: WorkspaceHeadSnapshot,
}

/// Locks the singleton `workspace_write_head` row and returns its snapshot
/// plus the fixed Workspace identity.
fn lock_workspace_head(transaction: &mut Transaction) -> Result<HeadRow, PgError> {
    let row = transaction
        .query_opt(
            "SELECT workspace_id, transaction_sequence, authority_sequence, content_sequence,
                    release_sequence, authority_head_digest, authority_head_sequence,
                    content_head_digest, release_head_digest, policy_head_digest,
                    configuration_head_digest
             FROM workspace_write_head WHERE singleton = 1 FOR UPDATE",
            &[],
        )
        .map_err(projection_error)?;
    let row =
        row.ok_or_else(|| PgError::Projection("the Workspace write head is absent".to_owned()))?;

    let workspace_id_text: String = row.get(0);
    let workspace_id = workspace_id_text
        .parse::<WorkspaceId>()
        .map_err(|error| PgError::Projection(format!("invalid Workspace identity: {error}")))?;

    let authority_head = match (
        row.get::<_, Option<String>>(5),
        row.get::<_, Option<i64>>(6),
    ) {
        (Some(digest), Some(sequence)) => Some(AuthorityHeadV1 {
            sequence: u64::try_from(sequence).map_err(|_| {
                PgError::Projection("authority head sequence is negative".to_owned())
            })?,
            record_digest: digest
                .parse()
                .map_err(|error| PgError::Projection(format!("invalid authority head: {error}")))?,
        }),
        (None, None) => None,
        _ => {
            return Err(PgError::Projection(
                "authority head digest and sequence disagree on presence".to_owned(),
            ));
        }
    };

    let snapshot = WorkspaceHeadSnapshot {
        transaction_sequence: row
            .get::<_, i64>(1)
            .try_into()
            .map_err(|_| PgError::Projection("transaction sequence is negative".to_owned()))?,
        authority_sequence: row
            .get::<_, i64>(2)
            .try_into()
            .map_err(|_| PgError::Projection("authority sequence is negative".to_owned()))?,
        content_sequence: row
            .get::<_, i64>(3)
            .try_into()
            .map_err(|_| PgError::Projection("content sequence is negative".to_owned()))?,
        release_sequence: row
            .get::<_, i64>(4)
            .try_into()
            .map_err(|_| PgError::Projection("release sequence is negative".to_owned()))?,
        authority_head,
        content_head: parse_optional_digest(row.get::<_, Option<String>>(7), "content head")?,
        release_head: parse_optional_digest(row.get::<_, Option<String>>(8), "release head")?,
        policy_head: parse_optional_digest(row.get::<_, Option<String>>(9), "policy head")?,
        configuration_head: parse_optional_digest(
            row.get::<_, Option<String>>(10),
            "configuration head",
        )?,
    };

    Ok(HeadRow {
        workspace_id,
        snapshot,
    })
}

fn parse_optional_digest(
    value: Option<String>,
    label: &str,
) -> Result<Option<ContentDigest>, PgError> {
    value
        .map(|text| {
            text.parse()
                .map_err(|error| PgError::Projection(format!("invalid {label}: {error}")))
        })
        .transpose()
}

/// One verified canonical content/Release fact read from the `facts` table.
struct VerifiedFact {
    fact_id: String,
    fact_kind: String,
    authority_sequence: i64,
    fact_digest: ContentDigest,
    body: Value,
}

/// Rebuilds the derived rows into the next generation inside an already-open
/// serializable transaction and returns the generation descriptor. Callers own
/// commit/rollback so the import can commit the cutover atomically.
pub(crate) fn rebuild_generation_in_transaction(
    transaction: &mut Transaction,
) -> Result<ProjectionGeneration, PgError> {
    rebuild_generation(transaction, true)
}

fn rebuild_generation(
    transaction: &mut Transaction,
    verify_authority: bool,
) -> Result<ProjectionGeneration, PgError> {
    let head = lock_workspace_head(transaction)?;

    // Verify the authority, content, and Release chains and cross-check the
    // locked head row against the reconstructed chains.
    if verify_authority {
        verify_authority_chain(transaction, head.snapshot.authority_head)?;
        verify_remote_authority_chain(transaction)?;
    }
    let facts = read_verified_facts(transaction)?;
    verify_content_chain(&facts, head.snapshot.content_sequence)?;
    verify_release_chain(&facts, head.snapshot.release_sequence)?;

    // Rebuild every derived row into the next generation.
    let next_generation = next_generation_number(transaction)?;
    let counts = materialize_derived_rows(transaction, next_generation, &facts)?;
    let state_digest = compute_state_digest(transaction, next_generation, &head)?;
    verify_state_digest_matches_head(&head, state_digest)?;

    // Commit the (inactive) generation descriptor atomically with its rows.
    let next_generation_bigint = generation_bigint(next_generation)?;
    transaction
        .execute(
            "INSERT INTO projection_generations (generation, state_digest, active, rebuilt_at)
             VALUES ($1, $2, FALSE, $3)",
            &[
                &next_generation_bigint,
                &state_digest.to_string(),
                &SystemTime::now(),
            ],
        )
        .map_err(projection_error)?;

    Ok(ProjectionGeneration {
        generation: next_generation,
        heads: head.snapshot,
        counts,
        state_digest,
    })
}

/// Compares a built generation against the persisted derived rows and then
/// atomically flips the single active-generation pointer.
pub(crate) fn swap_active_generation_in_transaction(
    transaction: &mut Transaction,
    generation: &ProjectionGeneration,
) -> Result<(), PgError> {
    let head = lock_workspace_head(transaction)?;

    // Re-verify the persisted generation still reproduces the recorded heads,
    // counts, identities, foreign keys, versions, sequences, and state digest.
    let counts = persisted_counts(transaction, generation.generation)?;
    if counts != generation.counts {
        return Err(PgError::Projection(
            "rebuilt generation counts disagree with the persisted rows".to_owned(),
        ));
    }
    let state_digest = compute_state_digest(transaction, generation.generation, &head)?;
    if state_digest != generation.state_digest {
        return Err(PgError::Projection(
            "rebuilt generation state digest disagrees with the persisted rows".to_owned(),
        ));
    }
    verify_object_foreign_keys(transaction, generation.generation)?;

    let swapped = transaction
        .execute(
            "UPDATE projection_generations SET active = FALSE WHERE active = TRUE",
            &[],
        )
        .map_err(projection_error)?;
    let generation_bigint = generation_bigint(generation.generation)?;
    let activated = transaction
        .execute(
            "UPDATE projection_generations SET active = TRUE WHERE generation = $1",
            &[&generation_bigint],
        )
        .map_err(projection_error)?;
    if activated != 1 {
        return Err(PgError::Projection(format!(
            "generation {} was not found for activation",
            generation.generation
        )));
    }
    let active_count: i64 = transaction
        .query_one(
            "SELECT COUNT(*) FROM projection_generations WHERE active = TRUE",
            &[],
        )
        .map_err(projection_error)?
        .get(0);
    if active_count != 1 {
        return Err(PgError::Projection(format!(
            "projection swap left {active_count} active generations (swapped {swapped} off)"
        )));
    }
    Ok(())
}

/// Verifies the local authority chain: contiguous sequences from one, exact
/// predecessor linkage, and agreement with the recorded authority head.
fn verify_authority_chain(
    transaction: &mut Transaction,
    expected_head: Option<AuthorityHeadV1>,
) -> Result<(), PgError> {
    let rows = transaction
        .query(
            "SELECT authority_sequence, record_digest, predecessor_digest
             FROM authority_records ORDER BY authority_sequence",
            &[],
        )
        .map_err(projection_error)?;

    let mut previous_digest: Option<ContentDigest> = None;
    let mut head: Option<AuthorityHeadV1> = None;
    for (index, row) in rows.iter().enumerate() {
        let sequence = i64::try_from(index + 1)
            .map_err(|_| PgError::Projection("authority sequence overflow".to_owned()))?;
        let record_sequence: i64 = row.get(0);
        let record_digest: String = row.get(1);
        let predecessor: Option<String> = row.get(2);
        if record_sequence != sequence {
            return Err(PgError::Projection(
                "the authority chain has a sequence gap or reorder".to_owned(),
            ));
        }
        let record_digest = record_digest
            .parse::<ContentDigest>()
            .map_err(|error| PgError::Projection(format!("invalid authority digest: {error}")))?;
        let predecessor = predecessor
            .map(|text| text.parse::<ContentDigest>())
            .transpose()
            .map_err(|error| PgError::Projection(format!("invalid predecessor digest: {error}")))?;
        if predecessor != previous_digest {
            return Err(PgError::Projection(
                "the authority predecessor digest does not link to the previous record".to_owned(),
            ));
        }
        previous_digest = Some(record_digest);
        let record_sequence = u64::try_from(record_sequence)
            .map_err(|_| PgError::Projection("authority sequence is negative".to_owned()))?;
        head = Some(AuthorityHeadV1 {
            sequence: record_sequence,
            record_digest,
        });
    }

    if head != expected_head {
        return Err(PgError::Projection(
            "the reconstructed authority head disagrees with the recorded head".to_owned(),
        ));
    }
    Ok(())
}

/// Resolves a remote authority signing key from the key identifier embedded in
/// the first verified envelope. This is the DSSE self-describing key profile:
/// the resolver materializes the public key already bound to that identifier
/// after signature verification, so a switch or substitution fails closed.
struct SingleKeyResolver {
    key_id: String,
    public_key: [u8; 32],
}

impl ActiveAuthorityKeyResolver for SingleKeyResolver {
    fn resolve_active_key(&self, key_id: &str) -> Result<[u8; 32], RemoteError> {
        if key_id == self.key_id {
            Ok(self.public_key)
        } else {
            Err(RemoteError::Authority(format!(
                "no active remote authority key resolves for `{key_id}`"
            )))
        }
    }
}

/// Verifies the remote authority chain with `proof_remote::validate_chain`.
fn verify_remote_authority_chain(transaction: &mut Transaction) -> Result<(), PgError> {
    let rows = transaction
        .query(
            "SELECT authority_sequence, record_digest, envelope
             FROM remote_authority_records ORDER BY authority_sequence",
            &[],
        )
        .map_err(projection_error)?;
    if rows.is_empty() {
        return Ok(());
    }

    let mut records = Vec::with_capacity(rows.len());
    let mut resolver: Option<SingleKeyResolver> = None;
    for (expected_sequence, row) in (1_i64..).zip(rows) {
        let sequence: i64 = row.get(0);
        if sequence != expected_sequence {
            return Err(PgError::Projection(
                "the remote authority chain has a sequence gap or reorder".to_owned(),
            ));
        }
        let record_digest: String = row.get(1);
        let envelope: Vec<u8> = row.get(2);
        let parsed = parse_remote_authority_record_envelope(&envelope).map_err(projection_error)?;
        let key_id = parsed.key_id.clone();
        let verified = verify_remote_authority_record_envelope(&envelope, &key_id)
            .map_err(projection_error)?;
        if verified.parsed.payload_digest.to_string() != record_digest {
            return Err(PgError::Projection(
                "the remote authority record digest disagrees with its envelope payload".to_owned(),
            ));
        }
        let public_key = verified.public_key;
        records.push(VerifiedRemoteAuthorityRecord {
            record: verified.parsed.record,
            record_digest: verified.parsed.payload_digest,
            envelope_digest: verified.parsed.envelope_digest,
            signer_key_id: key_id.clone(),
            public_key,
        });
        if let Some(existing) = &resolver
            && existing.key_id != key_id
        {
            return Err(PgError::Projection(
                "the remote authority chain switches signer keys within one prefix".to_owned(),
            ));
        }
        resolver.get_or_insert(SingleKeyResolver { key_id, public_key });
    }

    // The remote chain is validated against a zero head; a non-empty remote
    // prefix would otherwise begin at the recorded authority head.
    let initial_head = AuthorityHeadV1 {
        sequence: 0,
        record_digest: ContentDigest::blake3([0; 32]),
    };
    let resolver = resolver.expect("non-empty remote records must set a resolver");
    validate_chain(&records, &resolver, initial_head).map_err(projection_error)?;
    Ok(())
}

/// Reads and re-verifies every canonical fact from the `facts` table.
fn read_verified_facts(transaction: &mut Transaction) -> Result<Vec<VerifiedFact>, PgError> {
    let rows = transaction
        .query(
            "SELECT fact_id, fact_kind, authority_sequence, fact_digest, body
             FROM facts ORDER BY fact_id",
            &[],
        )
        .map_err(projection_error)?;

    let mut facts = Vec::with_capacity(rows.len());
    for row in rows {
        let fact_id: String = row.get(0);
        let fact_kind: String = row.get(1);
        let authority_sequence: i64 = row.get(2);
        let fact_digest: String = row.get(3);
        let body: Vec<u8> = row.get(4);

        let fact_digest = fact_digest
            .parse::<ContentDigest>()
            .map_err(|error| PgError::Projection(format!("invalid fact digest: {error}")))?;
        let Some(artifact_kind) = fact_artifact_kind(&fact_kind) else {
            continue;
        };
        let body_value = verify_canonical_digest(&body, artifact_kind, fact_digest, &fact_id)?;

        facts.push(VerifiedFact {
            fact_id,
            fact_kind,
            authority_sequence,
            fact_digest,
            body: body_value,
        });
    }
    Ok(facts)
}

/// Resolves the artifact kind used to digest one fact body.
fn fact_artifact_kind(fact_kind: &str) -> Option<ArtifactKind> {
    match fact_kind {
        FACT_KIND_SCHEMA => Some(ArtifactKind::SchemaVersionV1),
        FACT_KIND_OBJECT => Some(ArtifactKind::ObjectRevisionV1),
        FACT_KIND_RENDITION => Some(ArtifactKind::ObjectLocaleRevisionV1),
        FACT_KIND_RELEASE | "release_v1" => Some(ArtifactKind::ReleaseV1),
        "release_v2" => Some(ArtifactKind::ReleaseV2),
        // Non-content facts are verified by their own importers and do not
        // participate in the content projection.
        _ => None,
    }
}

/// Verifies the content chain: every schema/object/rendition fact carries a
/// positive, contiguous authority sequence exactly covering `1..=expected`.
fn verify_content_chain(facts: &[VerifiedFact], expected: u64) -> Result<(), PgError> {
    let mut sequences = facts
        .iter()
        .filter(|fact| matches!(fact.fact_kind.as_str(), "schema" | "object" | "rendition"))
        .map(|fact| fact.authority_sequence)
        .collect::<Vec<_>>();
    sequences.sort_unstable();
    let expected_len = usize::try_from(expected)
        .map_err(|_| PgError::Projection("content sequence exceeds addressable size".to_owned()))?;
    if sequences.len() != expected_len
        || sequences
            .iter()
            .enumerate()
            .any(|(index, actual)| *actual != i64::try_from(index + 1).unwrap_or(i64::MAX))
    {
        return Err(PgError::Projection(
            "the content chain sequences are incomplete or non-contiguous".to_owned(),
        ));
    }
    Ok(())
}

/// Returns whether a fact kind belongs to the Release chain.
fn is_release_kind(fact_kind: &str) -> bool {
    matches!(fact_kind, FACT_KIND_RELEASE | "release_v1" | "release_v2")
}

/// Verifies the Release chain: release facts carry contiguous release
/// sequences `1..=expected`.
fn verify_release_chain(facts: &[VerifiedFact], expected: u64) -> Result<(), PgError> {
    let mut sequences = facts
        .iter()
        .filter(|fact| is_release_kind(&fact.fact_kind))
        .map(|fact| fact.authority_sequence)
        .collect::<Vec<_>>();
    sequences.sort_unstable();
    let expected_len = usize::try_from(expected)
        .map_err(|_| PgError::Projection("release sequence exceeds addressable size".to_owned()))?;
    if sequences.len() != expected_len
        || sequences
            .iter()
            .enumerate()
            .any(|(index, actual)| *actual != i64::try_from(index + 1).unwrap_or(i64::MAX))
    {
        return Err(PgError::Projection(
            "the Release chain sequences are incomplete or non-contiguous".to_owned(),
        ));
    }
    Ok(())
}

/// The next monotonic generation number derived from the existing pointer rows.
fn next_generation_number(transaction: &mut Transaction) -> Result<u64, PgError> {
    let max: Option<i64> = transaction
        .query_one(
            "SELECT COALESCE(MAX(generation), 0) FROM projection_generations",
            &[],
        )
        .map_err(projection_error)?
        .get(0);
    let next = u64::try_from(max.unwrap_or(0))
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| PgError::Projection("projection generation number overflow".to_owned()))?;
    Ok(next)
}

/// Materializes every derived row for `generation` from the verified facts and
/// returns the per-kind counts.
fn materialize_derived_rows(
    transaction: &mut Transaction,
    generation: u64,
    facts: &[VerifiedFact],
) -> Result<ProjectionCounts, PgError> {
    let generation_bigint = generation_bigint(generation)?;
    let mut counts = ProjectionCounts::default();
    for fact in facts {
        match fact.fact_kind.as_str() {
            FACT_KIND_SCHEMA => {
                let (schema_id, schema_version) = parse_schema_fact_id(&fact.fact_id)?;
                transaction
                    .execute(
                        "INSERT INTO projection_schemas (
                             generation, schema_id, schema_version, document_digest,
                             authority_sequence
                         ) VALUES ($1, $2, $3, $4, $5)",
                        &[
                            &generation_bigint,
                            &schema_id.as_str(),
                            &i64::from(schema_version.get()),
                            &fact.fact_digest.to_string(),
                            &fact.authority_sequence,
                        ],
                    )
                    .map_err(projection_error)?;
                counts.schemas += 1;
            }
            FACT_KIND_OBJECT => {
                let object = parse_object_fact(&fact.body, fact.fact_digest)?;
                transaction
                    .execute(
                        "INSERT INTO projection_objects (
                             generation, object_id, revision, schema_id, schema_version,
                             lifecycle_state, object_digest, authority_sequence
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                        &[
                            &generation_bigint,
                            &object.object_id.to_string(),
                            &i64::from(object.revision.get()),
                            &object.schema_id.as_str(),
                            &i64::from(object.schema_version.get()),
                            &object.lifecycle_state.to_string(),
                            &object.object_digest.to_string(),
                            &fact.authority_sequence,
                        ],
                    )
                    .map_err(projection_error)?;
                counts.objects += 1;
            }
            FACT_KIND_RENDITION => {
                let rendition = parse_rendition_fact(&fact.body, fact.fact_digest)?;
                transaction
                    .execute(
                        "INSERT INTO projection_renditions (
                             generation, object_id, locale, revision, rendition_digest,
                             source_object_digest, schema_id, schema_version,
                             authority_sequence
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                        &[
                            &generation_bigint,
                            &rendition.object_id.to_string(),
                            &rendition.locale.as_str(),
                            &i64::from(rendition.revision.get()),
                            &rendition.rendition_digest.to_string(),
                            &rendition.source_object_digest.to_string(),
                            &rendition.schema_id.as_str(),
                            &i64::from(rendition.schema_version.get()),
                            &fact.authority_sequence,
                        ],
                    )
                    .map_err(projection_error)?;
                counts.renditions += 1;
            }
            FACT_KIND_RELEASE | "release_v1" | "release_v2" => {
                let (release_id, release_sequence) = parse_release_fact(&fact.body)?;
                let release_sequence_bigint = i64::try_from(release_sequence).map_err(|_| {
                    PgError::Projection("release sequence exceeds BIGINT range".to_owned())
                })?;
                transaction
                    .execute(
                        "INSERT INTO projection_releases (
                             generation, release_id, release_sequence, release_digest
                         ) VALUES ($1, $2, $3, $4)",
                        &[
                            &generation_bigint,
                            &release_id,
                            &release_sequence_bigint,
                            &fact.fact_digest.to_string(),
                        ],
                    )
                    .map_err(projection_error)?;
                counts.releases += 1;
            }
            other => {
                return Err(PgError::Projection(format!(
                    "unsupported fact kind `{other}` during rebuild"
                )));
            }
        }
    }
    Ok(counts)
}

/// Computes the domain-separated Known State digest plus per-kind counts for a
/// persisted generation.
fn compute_state_digest(
    transaction: &mut Transaction,
    generation: u64,
    head: &HeadRow,
) -> Result<ContentDigest, PgError> {
    let schemas = read_schema_projections(transaction, generation)?;
    let objects = read_object_projections(transaction, generation)?;
    let state_api_version: Option<String> = transaction
        .query_opt(
            "SELECT body FROM facts WHERE fact_kind = 'known_state_head' LIMIT 1",
            &[],
        )
        .map_err(projection_error)?
        .map(|row| {
            let body: Vec<u8> = row.get(0);
            serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|value| {
                    value
                        .get("known_state_api_version")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .ok_or_else(|| {
                    PgError::Projection("the Known State head fact is malformed".to_owned())
                })
        })
        .transpose()?;
    if state_api_version.as_deref() == Some(proof_application::KNOWN_STATE_V2_API_VERSION) {
        let renditions = read_locale_state_refs(transaction, generation)?;
        let previous = read_previous_artifact(transaction, head.snapshot.content_sequence)?;
        let manifest = proof_canonical::known_state_v2_manifest(
            head.workspace_id,
            head.snapshot.content_sequence,
            &schemas,
            &objects,
            &renditions,
            &previous,
        )
        .map_err(projection_error)?;
        return Ok(digest(ArtifactKind::KnownStateV2, &manifest));
    }
    known_state_digest_with_objects(
        head.workspace_id,
        head.snapshot.content_sequence,
        &schemas,
        &objects,
    )
    .map_err(projection_error)
}

/// Reads deduplicated highest-revision locale references for one generation.
fn read_locale_state_refs(
    transaction: &mut Transaction,
    generation: u64,
) -> Result<Vec<proof_canonical::LocaleStateReference>, PgError> {
    let generation_bigint = generation_bigint(generation)?;
    let rows = transaction
        .query(
            "SELECT object_id, locale, revision, rendition_digest, source_object_digest,
                    schema_id, schema_version
             FROM projection_renditions WHERE generation = $1
             ORDER BY object_id, locale, revision",
            &[&generation_bigint],
        )
        .map_err(projection_error)?;
    let mut heads =
        std::collections::BTreeMap::<(String, String), proof_canonical::LocaleStateReference>::new(
        );
    for row in rows {
        let parse_digest = |text: String| -> Result<ContentDigest, PgError> {
            text.parse()
                .map_err(|error| PgError::Projection(format!("invalid rendition digest: {error}")))
        };
        let object_id: String = row.get(0);
        let locale_text: String = row.get(1);
        let parsed_object_id: proof_domain::ObjectId =
            object_id.parse::<proof_domain::ObjectId>().map_err(
                |error: proof_domain::IdentifierError| PgError::Projection(error.to_string()),
            )?;
        let reference = proof_canonical::LocaleStateReference {
            object_id: parsed_object_id,
            locale: locale_text
                .parse()
                .map_err(|_| PgError::Projection("invalid projected locale".to_owned()))?,
            revision: proof_application::LocaleRevision::new(
                u32::try_from(row.get::<_, i64>(2))
                    .map_err(|_| PgError::Projection("rendition revision overflow".to_owned()))?,
            )
            .map_err(projection_error)?,
            rendition_digest: parse_digest(row.get(3))?,
            source_object_digest: parse_digest(row.get(4))?,
            schema_id: SchemaId::new(row.get::<_, String>(5)).map_err(projection_error)?,
            schema_version: SchemaVersion::new(
                u32::try_from(row.get::<_, i64>(6))
                    .map_err(|_| PgError::Projection("schema version overflow".to_owned()))?,
            )
            .map_err(projection_error)?,
        };
        heads.insert((object_id, locale_text), reference);
    }
    Ok(heads.into_values().collect())
}

/// Reads the highest Known State artifact recorded below the current head.
fn read_previous_artifact(
    transaction: &mut Transaction,
    below_sequence: u64,
) -> Result<proof_canonical::PreviousKnownStateReference, PgError> {
    let rows = transaction
        .query(
            "SELECT body FROM facts WHERE fact_kind = 'known_state_artifact'
             ORDER BY fact_id DESC",
            &[],
        )
        .map_err(projection_error)?;
    for row in rows {
        let body: Vec<u8> = row.get(0);
        let value: Value = serde_json::from_slice(&body).map_err(projection_error)?;
        let sequence = value
            .get("authoritative_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| PgError::Projection("artifact lacks sequence".to_owned()))?;
        if sequence == below_sequence {
            let previous = value
                .get("manifest")
                .and_then(|manifest| manifest.get("previous_state"));
            if let Some(previous) = previous {
                return Ok(proof_canonical::PreviousKnownStateReference {
                    api_version: previous
                        .get("api_version")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            PgError::Projection(
                                "current artifact predecessor lacks api version".to_owned(),
                            )
                        })?
                        .to_owned(),
                    authoritative_sequence: previous
                        .get("authoritative_sequence")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| {
                            PgError::Projection(
                                "current artifact predecessor lacks sequence".to_owned(),
                            )
                        })?,
                    digest: previous
                        .get("digest")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            PgError::Projection(
                                "current artifact predecessor lacks digest".to_owned(),
                            )
                        })?
                        .parse()
                        .map_err(|error| {
                            PgError::Projection(format!(
                                "invalid current artifact predecessor digest: {error}"
                            ))
                        })?,
                });
            }
        }
        if sequence >= below_sequence {
            continue;
        }
        return Ok(proof_canonical::PreviousKnownStateReference {
            api_version: value
                .get("artifact_api_version")
                .and_then(Value::as_str)
                .ok_or_else(|| PgError::Projection("artifact lacks api version".to_owned()))?
                .to_owned(),
            authoritative_sequence: sequence,
            digest: value
                .get("state_digest")
                .and_then(Value::as_str)
                .ok_or_else(|| PgError::Projection("artifact lacks digest".to_owned()))?
                .parse()
                .map_err(|error| {
                    PgError::Projection(format!("invalid artifact digest: {error}"))
                })?,
        });
    }
    Err(PgError::Projection(
        "a v2 Known State lacks its predecessor artifact".to_owned(),
    ))
}

/// Confirms the freshly computed state digest matches the recorded content head.
fn verify_state_digest_matches_head(
    head: &HeadRow,
    state_digest: ContentDigest,
) -> Result<(), PgError> {
    if head.snapshot.content_head != Some(state_digest) {
        return Err(PgError::Projection(
            "the rebuilt state digest disagrees with the recorded content head".to_owned(),
        ));
    }
    Ok(())
}

/// Reads the derived Schema rows for one generation in canonical order.
fn read_schema_projections(
    transaction: &mut Transaction,
    generation: u64,
) -> Result<Vec<(SchemaId, SchemaVersion, ContentDigest)>, PgError> {
    let generation_bigint = generation_bigint(generation)?;
    let rows = transaction
        .query(
            "SELECT schema_id, schema_version, document_digest
             FROM projection_schemas WHERE generation = $1
             ORDER BY schema_id, schema_version",
            &[&generation_bigint],
        )
        .map_err(projection_error)?;
    let mut schemas = Vec::with_capacity(rows.len());
    for row in rows {
        let schema_id: String = row.get(0);
        let schema_version: i64 = row.get(1);
        let document_digest: String = row.get(2);
        let schema_id = SchemaId::new(schema_id)
            .map_err(|error| PgError::Projection(format!("invalid schema identity: {error}")))?;
        let schema_version = SchemaVersion::new(
            u32::try_from(schema_version)
                .map_err(|_| PgError::Projection("schema version is not positive".to_owned()))?,
        )
        .map_err(projection_error)?;
        let document_digest = document_digest
            .parse::<ContentDigest>()
            .map_err(|error| PgError::Projection(format!("invalid schema digest: {error}")))?;
        schemas.push((schema_id, schema_version, document_digest));
    }
    Ok(schemas)
}

/// Reads the derived Object rows for one generation in canonical order.
fn read_object_projections(
    transaction: &mut Transaction,
    generation: u64,
) -> Result<Vec<ObjectStateReference>, PgError> {
    let generation_bigint = generation_bigint(generation)?;
    let rows = transaction
        .query(
            "SELECT object_id, revision, schema_id, schema_version, lifecycle_state, object_digest
             FROM projection_objects WHERE generation = $1
             ORDER BY object_id, revision",
            &[&generation_bigint],
        )
        .map_err(projection_error)?;
    let mut objects = Vec::with_capacity(rows.len());
    for row in rows {
        let object_id: String = row.get(0);
        let revision: i64 = row.get(1);
        let schema_id: String = row.get(2);
        let schema_version: i64 = row.get(3);
        let lifecycle_state: String = row.get(4);
        let object_digest: String = row.get(5);
        objects.push(ObjectStateReference {
            object_id: object_id.parse().map_err(|error| {
                PgError::Projection(format!("invalid object identity: {error}"))
            })?,
            revision: proof_domain::ObjectRevision::new(
                u32::try_from(revision).map_err(|_| {
                    PgError::Projection("object revision is not positive".to_owned())
                })?,
            )
            .map_err(projection_error)?,
            schema_id: SchemaId::new(schema_id).map_err(|error| {
                PgError::Projection(format!("invalid schema identity: {error}"))
            })?,
            schema_version: SchemaVersion::new(
                u32::try_from(schema_version).map_err(|_| {
                    PgError::Projection("schema version is not positive".to_owned())
                })?,
            )
            .map_err(projection_error)?,
            lifecycle_state: proof_domain::ObjectLifecycleState::Active,
            object_digest: object_digest
                .parse()
                .map_err(|error| PgError::Projection(format!("invalid object digest: {error}")))?,
        });
        if lifecycle_state != "active" {
            return Err(PgError::Projection(
                "derived Object lifecycle state is not active".to_owned(),
            ));
        }
    }
    Ok(objects)
}

/// Reads per-kind counts for a persisted generation and verifies they agree.
fn persisted_counts(
    transaction: &mut Transaction,
    generation: u64,
) -> Result<ProjectionCounts, PgError> {
    let generation_bigint = generation_bigint(generation)?;
    let mut count = |table: &str| -> Result<u64, PgError> {
        let query = format!("SELECT COUNT(*) FROM {table} WHERE generation = $1");
        let value: i64 = transaction
            .query_one(&query, &[&generation_bigint])
            .map_err(projection_error)?
            .get(0);
        u64::try_from(value)
            .map_err(|_| PgError::Projection("negative projection count".to_owned()))
    };
    Ok(ProjectionCounts {
        objects: count("projection_objects")?,
        renditions: count("projection_renditions")?,
        schemas: count("projection_schemas")?,
        releases: count("projection_releases")?,
    })
}

/// Verifies every derived Object references a Schema that exists in the same
/// generation (foreign-key and version comparison).
fn verify_object_foreign_keys(
    transaction: &mut Transaction,
    generation: u64,
) -> Result<(), PgError> {
    let generation_bigint = generation_bigint(generation)?;
    let rows = transaction
        .query(
            "SELECT object_id, schema_id, schema_version FROM projection_objects
             WHERE generation = $1 ORDER BY object_id, revision",
            &[&generation_bigint],
        )
        .map_err(projection_error)?;
    for row in rows {
        let object_id: String = row.get(0);
        let schema_id: String = row.get(1);
        let schema_version: i64 = row.get(2);
        let found: Option<i64> = transaction
            .query_opt(
                "SELECT 1 FROM projection_schemas
                 WHERE generation = $1 AND schema_id = $2 AND schema_version = $3",
                &[&generation_bigint, &schema_id.as_str(), &schema_version],
            )
            .map_err(projection_error)?
            .map(|_| 1);
        if found.is_none() {
            return Err(PgError::Projection(format!(
                "derived Object `{object_id}` references missing Schema `{schema_id}`@{schema_version}"
            )));
        }
    }
    Ok(())
}

/// Verifies one canonical body reproduces its recorded digest.
pub(crate) fn verify_canonical_digest(
    body: &[u8],
    kind: ArtifactKind,
    expected: ContentDigest,
    label: &str,
) -> Result<Value, PgError> {
    let value = parse_strict(body).map_err(|error| {
        PgError::Projection(format!("{label}: invalid canonical JSON: {error}"))
    })?;
    let canonical = canonicalize(&value).map_err(|error| {
        PgError::Projection(format!("{label}: canonicalization failed: {error}"))
    })?;
    if canonical.as_bytes() != body {
        return Err(PgError::Projection(format!(
            "{label}: bytes are not canonical JSON"
        )));
    }
    let recomputed = digest(kind, &canonical);
    if recomputed != expected {
        return Err(PgError::Projection(format!("{label}: digest mismatch")));
    }
    Ok(value)
}

/// Parses a schema fact identity `schema/{schema_id}/{schema_version}`.
pub(crate) fn parse_schema_fact_id(fact_id: &str) -> Result<(SchemaId, SchemaVersion), PgError> {
    let parts = fact_id.split('/').collect::<Vec<_>>();
    if parts.len() != 3 || parts[0] != FACT_KIND_SCHEMA {
        return Err(PgError::Projection(format!(
            "malformed schema fact identity `{fact_id}`"
        )));
    }
    let schema_id = SchemaId::new(parts[1])
        .map_err(|error| PgError::Projection(format!("invalid schema identity: {error}")))?;
    let schema_version = parts[2]
        .parse::<u32>()
        .ok()
        .and_then(|value| SchemaVersion::new(value).ok())
        .ok_or_else(|| PgError::Projection(format!("invalid schema version in `{fact_id}`")))?;
    Ok((schema_id, schema_version))
}

/// Parses an Object fact body (the canonical `ObjectRevisionV1` manifest).
pub(crate) fn parse_object_fact(
    body: &Value,
    fact_digest: ContentDigest,
) -> Result<ObjectStateReference, PgError> {
    let object_id = body
        .get("object_id")
        .and_then(Value::as_str)
        .ok_or_else(|| PgError::Projection("Object fact body lacks object_id".to_owned()))?;
    let revision = body
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or_else(|| PgError::Projection("Object fact body lacks revision".to_owned()))?;
    let schema_id = body
        .get("schema_id")
        .and_then(Value::as_str)
        .ok_or_else(|| PgError::Projection("Object fact body lacks schema_id".to_owned()))?;
    let schema_version = body
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| PgError::Projection("Object fact body lacks schema_version".to_owned()))?;
    let lifecycle_state = body
        .get("lifecycle_state")
        .and_then(Value::as_str)
        .ok_or_else(|| PgError::Projection("Object fact body lacks lifecycle_state".to_owned()))?;
    Ok(ObjectStateReference {
        object_id: object_id
            .parse()
            .map_err(|error| PgError::Projection(format!("invalid object identity: {error}")))?,
        revision: proof_domain::ObjectRevision::new(
            u32::try_from(revision)
                .map_err(|_| PgError::Projection("object revision is not positive".to_owned()))?,
        )
        .map_err(projection_error)?,
        schema_id: SchemaId::new(schema_id)
            .map_err(|error| PgError::Projection(format!("invalid schema identity: {error}")))?,
        schema_version: SchemaVersion::new(
            u32::try_from(schema_version)
                .map_err(|_| PgError::Projection("schema version is not positive".to_owned()))?,
        )
        .map_err(projection_error)?,
        lifecycle_state: match lifecycle_state {
            "active" => proof_domain::ObjectLifecycleState::Active,
            other => {
                return Err(PgError::Projection(format!(
                    "unsupported Object lifecycle state `{other}`"
                )));
            }
        },
        object_digest: fact_digest,
    })
}

/// One derived exact-locale rendition row.
struct RenditionProjection {
    object_id: proof_domain::ObjectId,
    locale: proof_domain::LocaleId,
    revision: proof_domain::LocaleRevision,
    rendition_digest: ContentDigest,
    source_object_digest: ContentDigest,
    schema_id: SchemaId,
    schema_version: SchemaVersion,
}

/// Parses a rendition fact body (the canonical `ObjectLocaleRevisionV1` manifest).
fn parse_rendition_fact(
    body: &Value,
    fact_digest: ContentDigest,
) -> Result<RenditionProjection, PgError> {
    let object_id = body
        .get("object_id")
        .and_then(Value::as_str)
        .ok_or_else(|| PgError::Projection("rendition fact body lacks object_id".to_owned()))?;
    let locale = body
        .get("locale")
        .and_then(Value::as_str)
        .ok_or_else(|| PgError::Projection("rendition fact body lacks locale".to_owned()))?;
    let revision = body
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or_else(|| PgError::Projection("rendition fact body lacks revision".to_owned()))?;
    let source_object_digest = body
        .get("source_object_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PgError::Projection("rendition fact body lacks source_object_digest".to_owned())
        })?;
    let schema_id = body
        .get("schema_id")
        .and_then(Value::as_str)
        .ok_or_else(|| PgError::Projection("rendition fact body lacks schema_id".to_owned()))?;
    let schema_version = body
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            PgError::Projection("rendition fact body lacks schema_version".to_owned())
        })?;
    Ok(RenditionProjection {
        object_id: object_id
            .parse()
            .map_err(|error| PgError::Projection(format!("invalid object identity: {error}")))?,
        locale: locale
            .parse()
            .map_err(|error| PgError::Projection(format!("invalid locale: {error}")))?,
        revision: proof_domain::LocaleRevision::new(
            u32::try_from(revision).map_err(|_| {
                PgError::Projection("rendition revision is not positive".to_owned())
            })?,
        )
        .map_err(projection_error)?,
        rendition_digest: fact_digest,
        source_object_digest: source_object_digest.parse().map_err(|error| {
            PgError::Projection(format!("invalid source object digest: {error}"))
        })?,
        schema_id: SchemaId::new(schema_id)
            .map_err(|error| PgError::Projection(format!("invalid schema identity: {error}")))?,
        schema_version: SchemaVersion::new(
            u32::try_from(schema_version)
                .map_err(|_| PgError::Projection("schema version is not positive".to_owned()))?,
        )
        .map_err(projection_error)?,
    })
}

/// Parses a Release fact body (the canonical release manifest) for identity and
/// sequence.
fn parse_release_fact(body: &Value) -> Result<(String, u64), PgError> {
    let release_id = body
        .get("release_id")
        .and_then(Value::as_str)
        .ok_or_else(|| PgError::Projection("release fact body lacks release_id".to_owned()))?;
    let release_sequence = body
        .get("release_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            PgError::Projection("release fact body lacks release_sequence".to_owned())
        })?;
    Ok((release_id.to_owned(), release_sequence))
}
