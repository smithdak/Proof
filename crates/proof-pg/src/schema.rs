//! Exact logged-table DDL constants (contract §"PostgreSQL authoritative unit
//! of work", §"Migration and projection rebuild", §"Immutable artifact
//! boundary", §"Transactional outbox and delivery").
//!
//! Every authoritative table is ordinary LOGGED storage; no `UNLOGGED`
//! authoritative table exists. The deployment must hold the contract
//! durability preconditions [`SYNCHRONOUS_COMMIT_REQUIRED`],
//! [`FSYNC_REQUIRED`], and [`FULL_PAGE_WRITES_REQUIRED`] as `on`.

/// Required `synchronous_commit` value (contract §"PostgreSQL authoritative
/// unit of work").
///
/// This is a deployment precondition, not a value the DDL below enforces: the
/// schema only declares ordinary LOGGED tables, while the runtime verification
/// of `synchronous_commit`, `fsync`, and `full_page_writes` belongs to
/// [`PgRuntime::verify_durability_preconditions`](crate::wiring::PgRuntime::verify_durability_preconditions).
pub const SYNCHRONOUS_COMMIT_REQUIRED: &str = "on";
/// Required `fsync` value (contract §"PostgreSQL authoritative unit of work").
///
/// See [`SYNCHRONOUS_COMMIT_REQUIRED`]: a deployment precondition verified at
/// runtime, not by the schema.
pub const FSYNC_REQUIRED: &str = "on";
/// Required `full_page_writes` value (contract §"PostgreSQL authoritative unit
/// of work").
///
/// See [`SYNCHRONOUS_COMMIT_REQUIRED`]: a deployment precondition verified at
/// runtime, not by the schema.
pub const FULL_PAGE_WRITES_REQUIRED: &str = "on";

/// The singleton migration-head ledger table (contract §"Migration and
/// projection rebuild").
pub const MIGRATION_HEAD_DDL: &str = r"CREATE TABLE migration_head (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    version INTEGER NOT NULL CHECK (version > 0),
    name TEXT NOT NULL,
    script_digest TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('started', 'verified', 'failed')),
    actor TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ
);";

/// The singleton Workspace write-head row driving every causal sequence
/// (contract §"PostgreSQL authoritative unit of work").
pub const WORKSPACE_WRITE_HEAD_DDL: &str = r"CREATE TABLE workspace_write_head (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    workspace_id TEXT NOT NULL,
    migration_version INTEGER NOT NULL CHECK (migration_version > 0),
    transaction_sequence BIGINT NOT NULL,
    authority_sequence BIGINT NOT NULL,
    content_sequence BIGINT NOT NULL,
    release_sequence BIGINT NOT NULL,
    authority_head_digest TEXT,
    authority_head_sequence BIGINT,
    content_head_digest TEXT,
    release_head_digest TEXT,
    policy_head_digest TEXT,
    configuration_head_digest TEXT
);";

/// Append-only local authority records (contract §"PostgreSQL authoritative
/// unit of work").
pub const AUTHORITY_RECORDS_DDL: &str = r"CREATE TABLE authority_records (
    authority_sequence BIGINT PRIMARY KEY CHECK (authority_sequence > 0),
    workspace_id TEXT NOT NULL,
    record_digest TEXT NOT NULL UNIQUE,
    payload_type TEXT NOT NULL,
    payload BYTEA NOT NULL,
    predecessor_digest TEXT,
    committed_at TIMESTAMPTZ NOT NULL
);";

/// Append-only remote authority records (contract §"PostgreSQL authoritative
/// unit of work", §"Remote identity vocabulary").
pub const REMOTE_AUTHORITY_RECORDS_DDL: &str = r"CREATE TABLE remote_authority_records (
    authority_sequence BIGINT PRIMARY KEY CHECK (authority_sequence > 0),
    workspace_id TEXT NOT NULL,
    record_digest TEXT NOT NULL UNIQUE,
    envelope_digest TEXT NOT NULL UNIQUE,
    payload_type TEXT NOT NULL,
    envelope BYTEA NOT NULL,
    predecessor_digest TEXT,
    committed_at TIMESTAMPTZ NOT NULL
);";

/// Signed remote authorization decisions (contract §"PostgreSQL authoritative
/// unit of work").
pub const AUTHORIZATION_DECISIONS_DDL: &str = r"CREATE TABLE authorization_decisions (
    authority_sequence BIGINT PRIMARY KEY CHECK (authority_sequence > 0),
    workspace_id TEXT NOT NULL,
    decision_digest TEXT NOT NULL UNIQUE,
    operation TEXT NOT NULL,
    body BYTEA NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL
);";

/// Signed remote application consequences (contract §"PostgreSQL authoritative
/// unit of work").
pub const APPLICATION_CONSEQUENCES_DDL: &str = r"CREATE TABLE application_consequences (
    authority_sequence BIGINT PRIMARY KEY CHECK (authority_sequence > 0),
    workspace_id TEXT NOT NULL,
    consequence_digest TEXT NOT NULL UNIQUE,
    operation TEXT NOT NULL,
    application_effect_digest TEXT,
    body BYTEA NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL
);";

/// Governed facts (content, authority, and configuration facts) (contract
/// §"PostgreSQL authoritative unit of work").
pub const FACTS_DDL: &str = r"CREATE TABLE facts (
    fact_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    fact_kind TEXT NOT NULL,
    authority_sequence BIGINT NOT NULL,
    fact_digest TEXT NOT NULL UNIQUE,
    body BYTEA NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL
);";

/// Keyed idempotency tuples and stored results (contract §"PostgreSQL
/// authoritative unit of work").
pub const IDEMPOTENCY_KEYS_DDL: &str = r"CREATE TABLE idempotency_keys (
    workspace_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    operation_version TEXT NOT NULL,
    normalized_input_digest TEXT NOT NULL,
    requesting_principal TEXT NOT NULL,
    operating_principal TEXT NOT NULL,
    delegation_id TEXT,
    application_key TEXT NOT NULL,
    key_kind TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    result_body BYTEA NOT NULL,
    replay_count BIGINT NOT NULL DEFAULT 0,
    committed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (workspace_id, application_key)
);";

/// The artifact catalog: identity plus storage location (contract §"Immutable
/// artifact boundary").
pub const ARTIFACT_CATALOG_DDL: &str = r"CREATE TABLE artifact_catalog (
    kind TEXT NOT NULL,
    digest TEXT NOT NULL,
    media_type TEXT NOT NULL,
    schema_version INTEGER,
    length BIGINT NOT NULL,
    stored_inline BOOLEAN NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (kind, digest)
);";

/// Immutable fork-capable signed artifact bodies stored atomically in
/// PostgreSQL (contract §"Immutable artifact boundary").
pub const ARTIFACT_BODY_PG_DDL: &str = r"CREATE TABLE artifact_body_pg (
    kind TEXT NOT NULL,
    digest TEXT NOT NULL,
    body BYTEA NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (kind, digest)
);";

/// Transactional outbox enqueue records (contract §"Transactional outbox and
/// delivery").
pub const OUTBOX_EVENTS_DDL: &str = r"CREATE TABLE outbox_events (
    event_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    workspace_transaction_sequence BIGINT NOT NULL,
    ordinal BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    event_version TEXT NOT NULL,
    ordering_key TEXT NOT NULL,
    stream_sequence BIGINT NOT NULL,
    effect_digest TEXT NOT NULL,
    payload_digest TEXT,
    artifact_kind TEXT,
    artifact_digest TEXT,
    destination_configuration_version BIGINT NOT NULL,
    destination_configuration_digest TEXT NOT NULL,
    correlation_id TEXT,
    causation_id TEXT,
    committed_creation_time TIMESTAMPTZ NOT NULL,
    UNIQUE (workspace_id, effect_digest, event_type, event_version, destination_configuration_digest),
    UNIQUE (workspace_id, workspace_transaction_sequence, ordinal)
);";

/// Append-only worker attempt records (contract §"Transactional outbox and
/// delivery"; the worker itself is a later item).
pub const ATTEMPTS_DDL: &str = r"CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    lease_token TEXT NOT NULL,
    status TEXT NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL,
    terminal_at TIMESTAMPTZ
);";

/// Terminal delivery receipts (contract §"Transactional outbox and delivery";
/// the worker itself is a later item).
pub const RECEIPTS_DDL: &str = r"CREATE TABLE receipts (
    receipt_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    observed_status TEXT NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE,
    recorded_at TIMESTAMPTZ NOT NULL
);";

/// Projection generations and the single active-generation pointer (contract
/// §"Migration and projection rebuild").
pub const PROJECTION_GENERATIONS_DDL: &str = r"CREATE TABLE projection_generations (
    generation BIGINT PRIMARY KEY CHECK (generation > 0),
    state_digest TEXT NOT NULL,
    active BOOLEAN NOT NULL,
    rebuilt_at TIMESTAMPTZ NOT NULL
);";

/// The exact ordered table list, all LOGGED, none UNLOGGED (contract
/// §"PostgreSQL authoritative unit of work").
pub const ALL_TABLE_DDL: [&str; 14] = [
    MIGRATION_HEAD_DDL,
    WORKSPACE_WRITE_HEAD_DDL,
    AUTHORITY_RECORDS_DDL,
    REMOTE_AUTHORITY_RECORDS_DDL,
    AUTHORIZATION_DECISIONS_DDL,
    APPLICATION_CONSEQUENCES_DDL,
    FACTS_DDL,
    IDEMPOTENCY_KEYS_DDL,
    ARTIFACT_CATALOG_DDL,
    ARTIFACT_BODY_PG_DDL,
    OUTBOX_EVENTS_DDL,
    ATTEMPTS_DDL,
    RECEIPTS_DDL,
    PROJECTION_GENERATIONS_DDL,
];
