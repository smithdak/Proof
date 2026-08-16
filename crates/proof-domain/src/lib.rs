#![forbid(unsafe_code)]

//! Deterministic domain types for Proof.
//!
//! This crate is intentionally independent of interface, persistence, async,
//! network, and telemetry libraries.

use std::{fmt, str::FromStr};

use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::{Uuid, Version};

/// An operational identifier was malformed or used the wrong UUID version.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdentifierError {
    /// The supplied value was not a UUID.
    #[error("the identifier is not a valid UUID")]
    InvalidUuid,
    /// Proof operational identifiers must be `UUIDv7` values.
    #[error("the identifier must use UUID version 7")]
    UnsupportedVersion,
}

macro_rules! operational_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Constructs an identifier after enforcing the `UUIDv7` invariant.
            ///
            /// # Errors
            ///
            /// Returns [`IdentifierError::UnsupportedVersion`] when `value`
            /// is not a version 7 UUID.
            pub fn from_uuid(value: Uuid) -> Result<Self, IdentifierError> {
                if value.get_version() == Some(Version::SortRand) {
                    Ok(Self(value))
                } else {
                    Err(IdentifierError::UnsupportedVersion)
                }
            }

            /// Returns the underlying UUID value.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let uuid = Uuid::parse_str(value).map_err(|_| IdentifierError::InvalidUuid)?;
                Self::from_uuid(uuid)
            }
        }
    };
}

operational_id!(OperationId, "The identity of one application operation.");
operational_id!(
    CorrelationId,
    "The identity connecting operations in one larger workflow."
);
operational_id!(WorkspaceId, "The identity of one governed Workspace.");
operational_id!(PrincipalId, "The identity of one authenticated Principal.");
operational_id!(
    ChangeSetId,
    "The identity of one atomic governed `ChangeSet`."
);
operational_id!(
    IdempotencyKey,
    "A caller-visible identity used to make an operation safely repeatable."
);
operational_id!(EditId, "The identity of one ordered `ChangeSet` Edit.");
operational_id!(ObjectId, "The identity of one governed content Object.");
operational_id!(
    EditionId,
    "The identity of one immutable Workspace Edition."
);

/// Maximum UTF-8 byte length of a logical Schema identifier.
pub const MAX_SCHEMA_ID_BYTES: usize = 128;

/// A stable, human-meaningful Schema identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchemaId(String);

impl SchemaId {
    /// Validates the initial lowercase logical identifier profile.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaIdError`] unless the value starts with a lowercase
    /// letter and contains only lowercase ASCII letters, digits, `.`, `_`, or
    /// `-` within [`MAX_SCHEMA_ID_BYTES`].
    pub fn new(value: impl Into<String>) -> Result<Self, SchemaIdError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_SCHEMA_ID_BYTES {
            return Err(SchemaIdError::InvalidLength);
        }
        let mut bytes = value.bytes();
        if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            || !bytes.all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(SchemaIdError::InvalidCharacters);
        }
        Ok(Self(value))
    }

    /// Returns the logical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SchemaId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A logical Schema identifier violated the initial profile.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SchemaIdError {
    /// The identifier was empty or too long.
    #[error("Schema identifier must contain 1 to {MAX_SCHEMA_ID_BYTES} UTF-8 bytes")]
    InvalidLength,
    /// The identifier used characters outside the stable lowercase profile.
    #[error(
        "Schema identifier must start with a lowercase letter and use only lowercase ASCII letters, digits, `.`, `_`, or `-`"
    )]
    InvalidCharacters,
}

/// A positive immutable Schema version number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchemaVersion(std::num::NonZeroU32);

impl SchemaVersion {
    /// Constructs a positive Schema version.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaVersionError`] for version zero.
    pub fn new(value: u32) -> Result<Self, SchemaVersionError> {
        std::num::NonZeroU32::new(value)
            .map(Self)
            .ok_or(SchemaVersionError)
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A Schema version must be positive.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Schema version must be greater than zero")]
pub struct SchemaVersionError;

/// A positive immutable Object revision number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectRevision(std::num::NonZeroU32);

impl ObjectRevision {
    /// The first accepted revision produced when an Object is created.
    pub const INITIAL: Self = Self(std::num::NonZeroU32::MIN);

    /// Constructs a positive Object revision.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectRevisionError`] for revision zero.
    pub fn new(value: u32) -> Result<Self, ObjectRevisionError> {
        std::num::NonZeroU32::new(value)
            .map(Self)
            .ok_or(ObjectRevisionError)
    }

    /// Returns the numeric revision.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for ObjectRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// An Object revision must be positive.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Object revision must be greater than zero")]
pub struct ObjectRevisionError;

/// The accepted lifecycle state of a governed content Object.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ObjectLifecycleState {
    /// The Object is active and eligible for inclusion in Editions.
    Active,
}

impl fmt::Display for ObjectLifecycleState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => formatter.write_str("active"),
        }
    }
}

/// Maximum UTF-8 byte length of a declared `ChangeSet` intent.
pub const MAX_CHANGESET_INTENT_BYTES: usize = 4_096;

/// A normalized, non-empty statement of why a `ChangeSet` exists.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ChangeSetIntent(String);

impl ChangeSetIntent {
    /// Normalizes and validates a declared intent.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetIntentError`] when the normalized intent is empty or
    /// exceeds [`MAX_CHANGESET_INTENT_BYTES`].
    pub fn new(value: impl Into<String>) -> Result<Self, ChangeSetIntentError> {
        let value = value.into().trim().to_owned();
        if value.is_empty() {
            return Err(ChangeSetIntentError::Empty);
        }
        if value.len() > MAX_CHANGESET_INTENT_BYTES {
            return Err(ChangeSetIntentError::TooLong);
        }
        Ok(Self(value))
    }

    /// Returns the normalized intent text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ChangeSetIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A declared `ChangeSet` intent was unsafe or incomplete.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ChangeSetIntentError {
    /// Whitespace normalization left no intent.
    #[error("ChangeSet intent must not be empty")]
    Empty,
    /// The intent exceeded the bounded command contract.
    #[error("ChangeSet intent must not exceed {MAX_CHANGESET_INTENT_BYTES} UTF-8 bytes")]
    TooLong,
}

/// A canonical RFC 3339 timestamp in UTC.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    /// Constructs a timestamp from nanoseconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns [`TimestampError::OutOfRange`] when the value cannot be
    /// represented by the timestamp contract.
    pub fn from_unix_timestamp_nanos(value: i128) -> Result<Self, TimestampError> {
        let value = OffsetDateTime::from_unix_timestamp_nanos(value)
            .map_err(|_| TimestampError::OutOfRange)?;
        value
            .format(&Rfc3339)
            .map_err(|_| TimestampError::OutOfRange)?;
        Ok(Self(value))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.0.format(&Rfc3339).map_err(|_| fmt::Error)?;
        formatter.write_str(&value)
    }
}

impl FromStr for Timestamp {
    type Err = TimestampError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !value.ends_with('Z') {
            return Err(TimestampError::NonCanonical);
        }
        let parsed =
            OffsetDateTime::parse(value, &Rfc3339).map_err(|_| TimestampError::InvalidRfc3339)?;
        let timestamp = Self(parsed);
        if timestamp.to_string() != value {
            return Err(TimestampError::NonCanonical);
        }
        Ok(timestamp)
    }
}

/// An external timestamp was invalid or non-canonical.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TimestampError {
    /// The value was outside the supported calendar range.
    #[error("timestamp is outside the supported range")]
    OutOfRange,
    /// The value was not RFC 3339.
    #[error("timestamp must use RFC 3339 syntax")]
    InvalidRfc3339,
    /// The value was not the canonical UTC `Z` representation.
    #[error("timestamp must use canonical UTC `Z` form")]
    NonCanonical,
}

/// The lifecycle state of one governed `ChangeSet`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ChangeSetStatus {
    /// The proposal may still receive Edits.
    Draft,
    /// Deterministic validation is executing.
    Validating,
    /// Validation passed for the exact proposal digest.
    Ready,
    /// The proposal was submitted for governed review.
    Submitted,
    /// Required approval has been recorded.
    Approved,
    /// The proposal atomically changed authoritative state.
    Committed,
    /// The proposal failed validation or policy.
    Rejected,
    /// A replacement proposal made this one obsolete.
    Superseded,
    /// The proposal exceeded its permitted lifetime.
    Expired,
}

impl fmt::Display for ChangeSetStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Draft => formatter.write_str("draft"),
            Self::Validating => formatter.write_str("validating"),
            Self::Ready => formatter.write_str("ready"),
            Self::Submitted => formatter.write_str("submitted"),
            Self::Approved => formatter.write_str("approved"),
            Self::Committed => formatter.write_str("committed"),
            Self::Rejected => formatter.write_str("rejected"),
            Self::Superseded => formatter.write_str("superseded"),
            Self::Expired => formatter.write_str("expired"),
        }
    }
}

/// The actor class associated with an authenticated Principal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrincipalType {
    /// A person authenticated through an identity provider.
    Human,
    /// A non-human service workload.
    Service,
    /// An autonomous or assisted software agent.
    Agent,
    /// An internal Proof runtime component.
    SystemComponent,
}

impl fmt::Display for PrincipalType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Human => formatter.write_str("human"),
            Self::Service => formatter.write_str("service"),
            Self::Agent => formatter.write_str("agent"),
            Self::SystemComponent => formatter.write_str("system_component"),
        }
    }
}

/// A versioned domain-artifact class used for cryptographic separation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ArtifactKind {
    /// A Workspace-wide immutable Edition manifest.
    EditionV1,
    /// An atomic `ChangeSet` manifest.
    ChangeSetV1,
    /// A bounded agent `ContextPack`.
    ContextPackV1,
    /// Validation findings bound to exact input.
    ValidationResultsV1,
    /// Reproducible authoritative Workspace state.
    KnownStateV1,
    /// An immutable JSON Schema version document.
    SchemaVersionV1,
    /// One ordered batch of typed `ChangeSet` Edits.
    EditBatchV1,
    /// One immutable ordered set of Schema versions.
    SchemaSetV1,
    /// One immutable accepted Object revision.
    ObjectRevisionV1,
    /// One immutable ordered set of Object revisions.
    ObjectSetV1,
}

impl ArtifactKind {
    /// Returns the stable BLAKE3 derive-key context for this artifact class.
    #[must_use]
    pub const fn derive_key_context(self) -> &'static str {
        match self {
            Self::EditionV1 => "proof:edition:v1",
            Self::ChangeSetV1 => "proof:changeset:v1",
            Self::ContextPackV1 => "proof:context-pack:v1",
            Self::ValidationResultsV1 => "proof:validation-results:v1",
            Self::KnownStateV1 => "proof:known-state:v1",
            Self::SchemaVersionV1 => "proof:schema-version:v1",
            Self::EditBatchV1 => "proof:edit-batch:v1",
            Self::SchemaSetV1 => "proof:schema-set:v1",
            Self::ObjectRevisionV1 => "proof:object-revision:v1",
            Self::ObjectSetV1 => "proof:object-set:v1",
        }
    }
}

/// A supported content-digest algorithm.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DigestAlgorithm {
    /// BLAKE3 with a 256-bit output and an artifact-specific derive-key context.
    Blake3,
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blake3 => formatter.write_str("blake3"),
        }
    }
}

/// An algorithm-qualified 256-bit content digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContentDigest {
    algorithm: DigestAlgorithm,
    bytes: [u8; 32],
}

impl ContentDigest {
    /// Constructs a domain-separated BLAKE3-256 digest value.
    #[must_use]
    pub const fn blake3(bytes: [u8; 32]) -> Self {
        Self {
            algorithm: DigestAlgorithm::Blake3,
            bytes,
        }
    }

    /// Returns the explicit digest algorithm.
    #[must_use]
    pub const fn algorithm(self) -> DigestAlgorithm {
        self.algorithm
    }

    /// Returns the 256-bit digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:", self.algorithm)?;
        for byte in self.bytes {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for ContentDigest {
    type Err = DigestParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (algorithm, encoded) = value
            .split_once(':')
            .ok_or(DigestParseError::MissingAlgorithm)?;
        if algorithm != "blake3" {
            return Err(DigestParseError::UnsupportedAlgorithm(algorithm.to_owned()));
        }
        if encoded.len() != 64 {
            return Err(DigestParseError::InvalidLength);
        }
        if !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DigestParseError::InvalidHex);
        }

        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&encoded[offset..offset + 2], 16)
                .map_err(|_| DigestParseError::InvalidHex)?;
        }
        Ok(Self::blake3(bytes))
    }
}

/// An algorithm-qualified digest string could not be parsed safely.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DigestParseError {
    /// The `algorithm:value` separator was absent.
    #[error("the digest must include an algorithm prefix")]
    MissingAlgorithm,
    /// The named algorithm is not supported by this implementation.
    #[error("unsupported digest algorithm `{0}`")]
    UnsupportedAlgorithm(String),
    /// The digest did not contain exactly 256 bits.
    #[error("the digest must contain exactly 64 lowercase hexadecimal characters")]
    InvalidLength,
    /// The digest contained a non-hexadecimal character.
    #[error("the digest contains invalid hexadecimal data")]
    InvalidHex,
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactKind, ChangeSetIntent, ChangeSetIntentError, ChangeSetStatus, ContentDigest,
        CorrelationId, DigestAlgorithm, DigestParseError, IdentifierError, ObjectId,
        ObjectLifecycleState, ObjectRevision, ObjectRevisionError, OperationId, PrincipalId,
        PrincipalType, SchemaId, SchemaIdError, SchemaVersion, SchemaVersionError, Timestamp,
        TimestampError,
    };
    use uuid::Uuid;

    const UUID_V7: &str = "019c0000-0000-7000-8000-000000000001";

    #[test]
    fn operational_ids_accept_uuid_v7() {
        let value = UUID_V7.parse::<OperationId>().expect("valid UUIDv7");

        assert_eq!(value.to_string(), UUID_V7);
        assert_eq!(value.as_uuid(), Uuid::parse_str(UUID_V7).unwrap());
    }

    #[test]
    fn principal_contract_has_stable_identity_and_actor_types() {
        let principal = UUID_V7.parse::<PrincipalId>().expect("valid UUIDv7");

        assert_eq!(principal.to_string(), UUID_V7);
        assert_eq!(PrincipalType::Human.to_string(), "human");
        assert_eq!(PrincipalType::Service.to_string(), "service");
        assert_eq!(PrincipalType::Agent.to_string(), "agent");
        assert_eq!(
            PrincipalType::SystemComponent.to_string(),
            "system_component"
        );
    }

    #[test]
    fn changeset_intent_is_trimmed_bounded_and_nonempty() {
        let intent = ChangeSetIntent::new("  Publish the launch article  ").unwrap();

        assert_eq!(intent.as_str(), "Publish the launch article");
        assert_eq!(
            ChangeSetIntent::new(" \n ").unwrap_err(),
            ChangeSetIntentError::Empty
        );
        assert_eq!(
            ChangeSetIntent::new("x".repeat(4_097)).unwrap_err(),
            ChangeSetIntentError::TooLong
        );
        assert_eq!(ChangeSetStatus::Draft.to_string(), "draft");
        assert_eq!(ChangeSetStatus::Committed.to_string(), "committed");
    }

    #[test]
    fn timestamps_use_canonical_rfc3339_utc_form() {
        let timestamp = "2026-08-03T14:00:00Z".parse::<Timestamp>().unwrap();

        assert_eq!(timestamp.to_string(), "2026-08-03T14:00:00Z");
        assert_eq!(
            "2026-08-03T09:00:00-05:00"
                .parse::<Timestamp>()
                .unwrap_err(),
            TimestampError::NonCanonical
        );
        assert_eq!(
            "not-a-time".parse::<Timestamp>().unwrap_err(),
            TimestampError::NonCanonical
        );
    }

    #[test]
    fn schema_identifiers_and_versions_have_a_stable_profile() {
        let schema_id = SchemaId::new("launch.article-v2").unwrap();
        let version = SchemaVersion::new(3).unwrap();

        assert_eq!(schema_id.as_str(), "launch.article-v2");
        assert_eq!(version.get(), 3);
        assert_eq!(
            SchemaId::new("Article").unwrap_err(),
            SchemaIdError::InvalidCharacters
        );
        assert_eq!(SchemaVersion::new(0).unwrap_err(), SchemaVersionError);
        assert_eq!(
            ArtifactKind::SchemaVersionV1.derive_key_context(),
            "proof:schema-version:v1"
        );
        assert_eq!(
            ArtifactKind::EditBatchV1.derive_key_context(),
            "proof:edit-batch:v1"
        );
    }

    #[test]
    fn object_identity_and_revisions_have_a_stable_profile() {
        let object_id = UUID_V7.parse::<ObjectId>().expect("valid UUIDv7");
        let revision = ObjectRevision::new(3).expect("positive revision");

        assert_eq!(object_id.to_string(), UUID_V7);
        assert_eq!(revision.get(), 3);
        assert_eq!(ObjectRevision::INITIAL.get(), 1);
        assert_eq!(ObjectRevision::new(0).unwrap_err(), ObjectRevisionError);
        assert_eq!(ObjectLifecycleState::Active.to_string(), "active");
        assert_eq!(
            ArtifactKind::ObjectRevisionV1.derive_key_context(),
            "proof:object-revision:v1"
        );
        assert_eq!(
            ArtifactKind::ObjectSetV1.derive_key_context(),
            "proof:object-set:v1"
        );
    }

    #[test]
    fn operational_ids_reject_other_uuid_versions() {
        let error = "550e8400-e29b-41d4-a716-446655440000"
            .parse::<CorrelationId>()
            .expect_err("UUIDv4 must be rejected");

        assert_eq!(error, IdentifierError::UnsupportedVersion);
    }

    #[test]
    fn operational_ids_reject_malformed_values() {
        let error = "not-a-uuid"
            .parse::<OperationId>()
            .expect_err("malformed UUID must be rejected");

        assert_eq!(error, IdentifierError::InvalidUuid);
    }

    #[test]
    fn artifact_contexts_are_explicit_and_versioned() {
        assert_eq!(
            ArtifactKind::EditionV1.derive_key_context(),
            "proof:edition:v1"
        );
        assert_ne!(
            ArtifactKind::EditionV1.derive_key_context(),
            ArtifactKind::ChangeSetV1.derive_key_context()
        );
    }

    #[test]
    fn content_digests_round_trip_with_an_algorithm_prefix() {
        let expected = ContentDigest::blake3([0xab; 32]);
        let encoded = format!("blake3:{}", "ab".repeat(32));
        let parsed = encoded.parse::<ContentDigest>().unwrap();

        assert_eq!(parsed, expected);
        assert_eq!(parsed.algorithm(), DigestAlgorithm::Blake3);
        assert_eq!(parsed.as_bytes(), &[0xab; 32]);
        assert_eq!(parsed.to_string(), encoded);
    }

    #[test]
    fn content_digests_reject_algorithm_confusion() {
        let encoded = format!("sha256:{}", "ab".repeat(32));
        let error = encoded.parse::<ContentDigest>().unwrap_err();

        assert_eq!(
            error,
            DigestParseError::UnsupportedAlgorithm("sha256".to_owned())
        );
    }

    #[test]
    fn content_digests_reject_noncanonical_uppercase_hex() {
        let encoded = format!("blake3:{}", "AB".repeat(32));

        assert_eq!(
            encoded.parse::<ContentDigest>().unwrap_err(),
            DigestParseError::InvalidHex
        );
    }
}
