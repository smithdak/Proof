//! Projection rebuild and atomic generation swap (contract §"Migration and
//! projection rebuild").

use std::time::SystemTime;

use postgres::{Client, IsolationLevel, Transaction};
use proof_canonical::{
    ObjectStateReference, canonicalize, digest, known_state_digest_with_objects, parse_strict,
};
use proof_domain::{ArtifactKind, ContentDigest, SchemaId, SchemaVersion, WorkspaceId};
use proof_remote::{
    ActiveAuthorityKeyResolver, AuthorityHeadV1, RemoteError, VerifiedRemoteAuthorityRecord,
    parse_remote_authority_record_envelope, validate_chain,
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

/// Converts a non-negative projection generation to its `BIGINT` binding form.
fn generation_bigint(generation: u64) -> Result<i64, PgError> {
    i64::try_from(generation)
        .map_err(|_| PgError::Projection("projection generation exceeds BIGINT range".to_owned()))
}

/// Ensures every derived projection table exists. Idempotent.
pub(crate) fn ensure_projection_tables(client: &mut Client) -> Result<(), PgError> {
    for ddl in DERIVED_TABLES_DDL {
        client
            .batch_execute(ddl)
            .map_err(|error| PgError::Projection(error.to_string()))?;
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
/// Returns [`PgError::Projection`] on chain verification or rebuild failure.
pub fn rebuild_into_new_generation(client: &mut Client) -> Result<ProjectionGeneration, PgError> {
    ensure_projection_tables(client)?;
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .read_only(false)
        .start()
        .map_err(|error| PgError::Projection(error.to_string()))?;
    let generation = rebuild_generation_in_transaction(&mut transaction)?;
    transaction
        .commit()
        .map_err(|error| PgError::Projection(error.to_string()))?;
    Ok(generation)
}

/// Atomically swaps the single active-generation pointer after comparing
/// identities, counts, foreign keys, versions, sequences, and state digest.
///
/// # Errors
///
/// Returns [`PgError::Projection`] when any comparison fails or the swap
/// cannot commit.
pub fn atomic_swap_active_generation(
    client: &mut Client,
    generation: &ProjectionGeneration,
) -> Result<(), PgError> {
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .read_only(false)
        .start()
        .map_err(|error| PgError::Projection(error.to_string()))?;
    swap_active_generation_in_transaction(&mut transaction, generation)?;
    transaction
        .commit()
        .map_err(|error| PgError::Projection(error.to_string()))?;
    Ok(())
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
        .map_err(|error| PgError::Projection(error.to_string()))?;
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
    let head = lock_workspace_head(transaction)?;

    // Verify the authority, content, and Release chains and cross-check the
    // locked head row against the reconstructed chains.
    verify_authority_chain(transaction, head.snapshot.authority_head)?;
    verify_remote_authority_chain(transaction)?;
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
        .map_err(|error| PgError::Projection(error.to_string()))?;

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
        .map_err(|error| PgError::Projection(error.to_string()))?;
    let generation_bigint = generation_bigint(generation.generation)?;
    let activated = transaction
        .execute(
            "UPDATE projection_generations SET active = TRUE WHERE generation = $1",
            &[&generation_bigint],
        )
        .map_err(|error| PgError::Projection(error.to_string()))?;
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
        .map_err(|error| PgError::Projection(error.to_string()))?
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
        .map_err(|error| PgError::Projection(error.to_string()))?;

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
        .map_err(|error| PgError::Projection(error.to_string()))?;
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
        let parsed = parse_remote_authority_record_envelope(&envelope)
            .map_err(|error| PgError::Projection(error.to_string()))?;
        let key_id = parsed.key_id.clone();
        let verified = verify_remote_authority_record_envelope(&envelope, &key_id)
            .map_err(|error| PgError::Projection(error.to_string()))?;
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
    validate_chain(&records, &resolver, initial_head)
        .map_err(|error| PgError::Projection(error.to_string()))?;
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
        .map_err(|error| PgError::Projection(error.to_string()))?;

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
        .map_err(|error| PgError::Projection(error.to_string()))?
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
                    .map_err(|error| PgError::Projection(error.to_string()))?;
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
                    .map_err(|error| PgError::Projection(error.to_string()))?;
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
                    .map_err(|error| PgError::Projection(error.to_string()))?;
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
                    .map_err(|error| PgError::Projection(error.to_string()))?;
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
        .map_err(|error| PgError::Projection(error.to_string()))?
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
        .map_err(|error| PgError::Projection(error.to_string()))?;
        return Ok(digest(ArtifactKind::KnownStateV2, &manifest));
    }
    known_state_digest_with_objects(
        head.workspace_id,
        head.snapshot.content_sequence,
        &schemas,
        &objects,
    )
    .map_err(|error| PgError::Projection(error.to_string()))
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
        .map_err(|error| PgError::Projection(error.to_string()))?;
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
            .map_err(|error| PgError::Projection(error.to_string()))?,
            rendition_digest: parse_digest(row.get(3))?,
            source_object_digest: parse_digest(row.get(4))?,
            schema_id: SchemaId::new(row.get::<_, String>(5))
                .map_err(|error| PgError::Projection(error.to_string()))?,
            schema_version: SchemaVersion::new(
                u32::try_from(row.get::<_, i64>(6))
                    .map_err(|_| PgError::Projection("schema version overflow".to_owned()))?,
            )
            .map_err(|error| PgError::Projection(error.to_string()))?,
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
        .map_err(|error| PgError::Projection(error.to_string()))?;
    for row in rows {
        let body: Vec<u8> = row.get(0);
        let value: Value = serde_json::from_slice(&body)
            .map_err(|error| PgError::Projection(error.to_string()))?;
        let sequence = value
            .get("authoritative_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| PgError::Projection("artifact lacks sequence".to_owned()))?;
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
        .map_err(|error| PgError::Projection(error.to_string()))?;
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
        .map_err(|error| PgError::Projection(error.to_string()))?;
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
        .map_err(|error| PgError::Projection(error.to_string()))?;
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
            .map_err(|error| PgError::Projection(error.to_string()))?,
            schema_id: SchemaId::new(schema_id).map_err(|error| {
                PgError::Projection(format!("invalid schema identity: {error}"))
            })?,
            schema_version: SchemaVersion::new(
                u32::try_from(schema_version).map_err(|_| {
                    PgError::Projection("schema version is not positive".to_owned())
                })?,
            )
            .map_err(|error| PgError::Projection(error.to_string()))?,
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
            .map_err(|error| PgError::Projection(error.to_string()))?
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
        .map_err(|error| PgError::Projection(error.to_string()))?;
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
            .map_err(|error| PgError::Projection(error.to_string()))?
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
        .map_err(|error| PgError::Projection(error.to_string()))?,
        schema_id: SchemaId::new(schema_id)
            .map_err(|error| PgError::Projection(format!("invalid schema identity: {error}")))?,
        schema_version: SchemaVersion::new(
            u32::try_from(schema_version)
                .map_err(|_| PgError::Projection("schema version is not positive".to_owned()))?,
        )
        .map_err(|error| PgError::Projection(error.to_string()))?,
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
        .map_err(|error| PgError::Projection(error.to_string()))?,
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
        .map_err(|error| PgError::Projection(error.to_string()))?,
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
