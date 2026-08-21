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
    BindingId,
    "The identity of one immutable Principal credential binding."
);
operational_id!(
    PresentationId,
    "The single-use identity of one authenticated command presentation."
);
operational_id!(
    EnrollmentChallengeId,
    "The single-use identity of one Principal-binding enrollment challenge."
);
operational_id!(
    RevocationId,
    "The identity of one immutable authority revocation record."
);
operational_id!(
    AuthorityRootTransitionId,
    "The identity of one planned Workspace authority-root transition."
);
operational_id!(
    DelegationId,
    "The identity of one immutable bounded authority Delegation."
);
operational_id!(
    ContextPackId,
    "The identity of one content-addressed agent `ContextPack`."
);
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
    ContentResourceIntentId,
    "The identity of one immutable localized-content resource intent."
);
operational_id!(
    EditionId,
    "The identity of one immutable Workspace Edition."
);
operational_id!(ReleaseId, "The identity of one immutable Release fact.");
operational_id!(ProofId, "The identity of one portable Proof artifact.");

/// Maximum UTF-8 byte length of a restricted exact locale identifier.
pub const MAX_LOCALE_ID_BYTES: usize = 64;

/// A case-sensitive locale identifier in Proof's restricted canonical profile.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LocaleId(String);

impl LocaleId {
    /// Validates Proof's deliberately restricted locale profile.
    ///
    /// The accepted grammar is a lowercase language subtag, optional title-case
    /// script, optional uppercase alpha or numeric region, and zero or more
    /// lowercase alphanumeric variants. Registry aliases are retained literally.
    ///
    /// # Errors
    ///
    /// Returns [`LocaleIdError`] when the value is empty, too long, malformed,
    /// or uses noncanonical casing.
    pub fn new(value: impl Into<String>) -> Result<Self, LocaleIdError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_LOCALE_ID_BYTES {
            return Err(LocaleIdError::InvalidLength);
        }
        let subtags = value.split('-').collect::<Vec<_>>();
        let Some(language) = subtags.first() else {
            return Err(LocaleIdError::InvalidSyntax);
        };
        if !(2..=8).contains(&language.len())
            || !language.bytes().all(|byte| byte.is_ascii_lowercase())
        {
            return Err(LocaleIdError::InvalidSyntax);
        }

        let mut index = 1;
        if subtags.get(index).is_some_and(|script| {
            script.len() == 4
                && script
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_uppercase())
                && script.bytes().skip(1).all(|byte| byte.is_ascii_lowercase())
        }) {
            index += 1;
        }
        if subtags.get(index).is_some_and(|region| {
            (region.len() == 2 && region.bytes().all(|byte| byte.is_ascii_uppercase()))
                || (region.len() == 3 && region.bytes().all(|byte| byte.is_ascii_digit()))
        }) {
            index += 1;
        }
        if subtags[index..].iter().any(|variant| {
            !((variant.len() >= 5
                && variant.len() <= 8
                && variant
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()))
                || (variant.len() == 4
                    && variant
                        .bytes()
                        .next()
                        .is_some_and(|byte| byte.is_ascii_digit())
                    && variant
                        .bytes()
                        .skip(1)
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())))
        }) {
            return Err(LocaleIdError::InvalidSyntax);
        }
        Ok(Self(value))
    }

    /// Returns the exact stored locale bytes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LocaleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for LocaleId {
    type Err = LocaleIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// A locale identifier violated Proof's restricted exact profile.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LocaleIdError {
    /// The locale was empty or exceeded the byte limit.
    #[error("locale must contain 1 to {MAX_LOCALE_ID_BYTES} UTF-8 bytes")]
    InvalidLength,
    /// The locale syntax or casing was outside the restricted profile.
    #[error("locale does not match Proof's restricted canonical profile")]
    InvalidSyntax,
}

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

impl FromStr for SchemaId {
    type Err = SchemaIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
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

/// Maximum UTF-8 byte length of a logical Environment identifier.
pub const MAX_ENVIRONMENT_ID_BYTES: usize = 128;

/// A stable lowercase delivery-target identifier such as `preview`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentId(String);

impl EnvironmentId {
    /// Validates the stable lowercase Environment identifier profile.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentIdError`] unless the value starts with a lowercase
    /// letter and uses only lowercase ASCII letters, digits, `.`, `_`, or `-`.
    pub fn new(value: impl Into<String>) -> Result<Self, EnvironmentIdError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_ENVIRONMENT_ID_BYTES {
            return Err(EnvironmentIdError::InvalidLength);
        }
        let mut bytes = value.bytes();
        if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            || !bytes.all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(EnvironmentIdError::InvalidCharacters);
        }
        Ok(Self(value))
    }

    /// Returns the logical Environment identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EnvironmentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for EnvironmentId {
    type Err = EnvironmentIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// A logical Environment identifier violated the stable profile.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EnvironmentIdError {
    /// The identifier was empty or too long.
    #[error("Environment identifier must contain 1 to {MAX_ENVIRONMENT_ID_BYTES} UTF-8 bytes")]
    InvalidLength,
    /// The identifier used unsupported characters.
    #[error(
        "Environment identifier must start with a lowercase letter and use only lowercase ASCII letters, digits, `.`, `_`, or `-`"
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

/// A positive immutable localized-rendition revision number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LocaleRevision(std::num::NonZeroU32);

impl LocaleRevision {
    /// The first accepted revision of an exact locale rendition.
    pub const INITIAL: Self = Self(std::num::NonZeroU32::MIN);

    /// Constructs a positive rendition revision.
    ///
    /// # Errors
    ///
    /// Returns [`LocaleRevisionError`] for revision zero.
    pub fn new(value: u32) -> Result<Self, LocaleRevisionError> {
        std::num::NonZeroU32::new(value)
            .map(Self)
            .ok_or(LocaleRevisionError)
    }

    /// Returns the numeric revision.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for LocaleRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A localized-rendition revision must be positive.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("locale rendition revision must be greater than zero")]
pub struct LocaleRevisionError;

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
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

    /// Returns nanoseconds since the Unix epoch for deterministic ordering and
    /// storage comparisons.
    #[must_use]
    pub const fn unix_timestamp_nanos(self) -> i128 {
        self.0.unix_timestamp_nanos()
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

/// The immutable reason a Release selected an Edition for an Environment.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReleaseKind {
    /// Select an Edition as the next forward release.
    Promotion,
    /// Select an Edition from an earlier Release without rewriting history.
    Rollback,
}

impl fmt::Display for ReleaseKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Promotion => formatter.write_str("promotion"),
            Self::Rollback => formatter.write_str("rollback"),
        }
    }
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
    /// One immutable result of an idempotent operation.
    OperationEffectV1,
    /// One immutable ordered set of Schema versions.
    SchemaSetV1,
    /// One immutable accepted Object revision.
    ObjectRevisionV1,
    /// One immutable ordered set of Object revisions.
    ObjectSetV1,
    /// One immutable versioned Environment configuration.
    EnvironmentConfigV1,
    /// One immutable Environment Release fact.
    ReleaseV1,
    /// One portable DSSE Proof envelope.
    ProofEnvelopeV1,
    /// One immutable bounded authority Delegation.
    DelegationV1,
    /// One immutable Agent Principal registration.
    PrincipalRegistrationV1,
    /// One deterministic authorization evaluation result.
    AuthorizationDecisionV1,
    /// One exact versioned policy bundle.
    PolicyBundleV1,
    /// One normalized authenticated semantic command.
    CommandV1,
    /// One authenticated-command DSSE envelope.
    AuthenticatedCommandEnvelopeV1,
    /// One single-use Agent binding-enrollment challenge.
    BindingEnrollmentChallengeV1,
    /// One binding-enrollment DSSE envelope.
    BindingEnrollmentEnvelopeV1,
    /// One hiding commitment to an authenticated requesting subject.
    AuthenticatedSubjectCommitmentV1,
    /// One persisted evidence-safe authenticated actor context.
    AuthenticatedActorContextV1,
    /// One typed append-only authority-log record.
    AuthorityRecordV1,
    /// One ordinary or root-transition authority DSSE envelope.
    AuthorityRecordEnvelopeV1,
    /// One immutable Human-issued localized-content resource intent.
    ContentResourceIntentV1,
    /// One exact localized-content source closure.
    ContextPackV2,
    /// One ordered batch of localized-content Edits.
    EditBatchV2,
    /// One immutable localized-content Edit.
    EditV2,
    /// One repairable localized-content `ChangeSet` proposal or seal.
    ChangeSetV2,
    /// One immutable localized-content validation attempt.
    ValidationResultsV2,
    /// One immutable exact-locale Object rendition revision.
    ObjectLocaleRevisionV1,
    /// One immutable set of source Objects and exact locale renditions.
    ObjectSetV2,
    /// One predecessor-bound rendition-aware Workspace state.
    KnownStateV2,
    /// One immutable rendition-aware Workspace Edition.
    EditionV2,
    /// One immutable localized-content Release fact.
    ReleaseV2,
    /// One portable index over a complete Release and authority evidence closure.
    AuthorityEvidenceBundleV1,
    /// One exported exact v13 authenticated localized consequence.
    AuthenticatedLocalizedConsequenceV1,
    /// One protected opening of an authenticated requesting-subject commitment.
    AuthenticatedSubjectOpeningV1,
    /// One independently retained authority-log checkpoint.
    AuthorityCheckpointV1,
    /// One explicit caller-supplied portable-verification trust policy.
    VerificationTrustPolicyV1,
    /// One deterministic structured portable-verification report.
    VerificationReportV1,
    /// One exported public Release-signing key validity record.
    ReleaseSigningKeyV1,
    /// One exported Release-signing key revocation record.
    ReleaseSigningKeyRevocationV1,
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
            Self::OperationEffectV1 => "proof:operation-effect:v1",
            Self::SchemaSetV1 => "proof:schema-set:v1",
            Self::ObjectRevisionV1 => "proof:object-revision:v1",
            Self::ObjectSetV1 => "proof:object-set:v1",
            Self::EnvironmentConfigV1 => "proof:environment-config:v1",
            Self::ReleaseV1 => "proof:release:v1",
            Self::ProofEnvelopeV1 => "proof:proof-envelope:v1",
            Self::DelegationV1 => "proof:delegation:v1",
            Self::PrincipalRegistrationV1 => "proof:principal-registration:v1",
            Self::AuthorizationDecisionV1 => "proof:authorization-decision:v1",
            Self::PolicyBundleV1 => "proof:policy-bundle:v1",
            Self::CommandV1 => "proof:command:v1",
            Self::AuthenticatedCommandEnvelopeV1 => "proof:authenticated-command-envelope:v1",
            Self::BindingEnrollmentChallengeV1 => "proof:binding-enrollment-challenge:v1",
            Self::BindingEnrollmentEnvelopeV1 => "proof:binding-enrollment-envelope:v1",
            Self::AuthenticatedSubjectCommitmentV1 => "proof:authenticated-subject-commitment:v1",
            Self::AuthenticatedActorContextV1 => "proof:authenticated-actor-context:v1",
            Self::AuthorityRecordV1 => "proof:authority-record:v1",
            Self::AuthorityRecordEnvelopeV1 => "proof:authority-record-envelope:v1",
            Self::ContentResourceIntentV1 => "proof:content-resource-intent:v1",
            Self::ContextPackV2 => "proof:context-pack:v2",
            Self::EditBatchV2 => "proof:edit-batch:v2",
            Self::EditV2 => "proof:edit:v2",
            Self::ChangeSetV2 => "proof:changeset:v2",
            Self::ValidationResultsV2 => "proof:validation-results:v2",
            Self::ObjectLocaleRevisionV1 => "proof:object-locale-revision:v1",
            Self::ObjectSetV2 => "proof:object-set:v2",
            Self::KnownStateV2 => "proof:known-state:v2",
            Self::EditionV2 => "proof:edition:v2",
            Self::ReleaseV2 => "proof:release:v2",
            Self::AuthorityEvidenceBundleV1 => "proof:authority-evidence-bundle:v1",
            Self::AuthenticatedLocalizedConsequenceV1 => {
                "proof:authenticated-localized-consequence:v1"
            }
            Self::AuthenticatedSubjectOpeningV1 => "proof:authenticated-subject-opening:v1",
            Self::AuthorityCheckpointV1 => "proof:authority-checkpoint:v1",
            Self::VerificationTrustPolicyV1 => "proof:verification-trust-policy:v1",
            Self::VerificationReportV1 => "proof:verification-report:v1",
            Self::ReleaseSigningKeyV1 => "proof:release-signing-key:v1",
            Self::ReleaseSigningKeyRevocationV1 => "proof:release-signing-key-revocation:v1",
        }
    }

    /// Returns the stable lowercase wire and content-addressed path name.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::EditionV1 => "edition_v1",
            Self::ChangeSetV1 => "changeset_v1",
            Self::ContextPackV1 => "context_pack_v1",
            Self::ValidationResultsV1 => "validation_results_v1",
            Self::KnownStateV1 => "known_state_v1",
            Self::SchemaVersionV1 => "schema_version_v1",
            Self::EditBatchV1 => "edit_batch_v1",
            Self::OperationEffectV1 => "operation_effect_v1",
            Self::SchemaSetV1 => "schema_set_v1",
            Self::ObjectRevisionV1 => "object_revision_v1",
            Self::ObjectSetV1 => "object_set_v1",
            Self::EnvironmentConfigV1 => "environment_config_v1",
            Self::ReleaseV1 => "release_v1",
            Self::ProofEnvelopeV1 => "proof_envelope_v1",
            Self::DelegationV1 => "delegation_v1",
            Self::PrincipalRegistrationV1 => "principal_registration_v1",
            Self::AuthorizationDecisionV1 => "authorization_decision_v1",
            Self::PolicyBundleV1 => "policy_bundle_v1",
            Self::CommandV1 => "command_v1",
            Self::AuthenticatedCommandEnvelopeV1 => "authenticated_command_envelope_v1",
            Self::BindingEnrollmentChallengeV1 => "binding_enrollment_challenge_v1",
            Self::BindingEnrollmentEnvelopeV1 => "binding_enrollment_envelope_v1",
            Self::AuthenticatedSubjectCommitmentV1 => "authenticated_subject_commitment_v1",
            Self::AuthenticatedActorContextV1 => "authenticated_actor_context_v1",
            Self::AuthorityRecordV1 => "authority_record_v1",
            Self::AuthorityRecordEnvelopeV1 => "authority_record_envelope_v1",
            Self::ContentResourceIntentV1 => "content_resource_intent_v1",
            Self::ContextPackV2 => "context_pack_v2",
            Self::EditBatchV2 => "edit_batch_v2",
            Self::EditV2 => "edit_v2",
            Self::ChangeSetV2 => "changeset_v2",
            Self::ValidationResultsV2 => "validation_results_v2",
            Self::ObjectLocaleRevisionV1 => "object_locale_revision_v1",
            Self::ObjectSetV2 => "object_set_v2",
            Self::KnownStateV2 => "known_state_v2",
            Self::EditionV2 => "edition_v2",
            Self::ReleaseV2 => "release_v2",
            Self::AuthorityEvidenceBundleV1 => "authority_evidence_bundle_v1",
            Self::AuthenticatedLocalizedConsequenceV1 => "authenticated_localized_consequence_v1",
            Self::AuthenticatedSubjectOpeningV1 => "authenticated_subject_opening_v1",
            Self::AuthorityCheckpointV1 => "authority_checkpoint_v1",
            Self::VerificationTrustPolicyV1 => "verification_trust_policy_v1",
            Self::VerificationReportV1 => "verification_report_v1",
            Self::ReleaseSigningKeyV1 => "release_signing_key_v1",
            Self::ReleaseSigningKeyRevocationV1 => "release_signing_key_revocation_v1",
        }
    }

    /// Resolves one exact stable wire name without aliases or case folding.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        ALL_ARTIFACT_KINDS
            .iter()
            .copied()
            .find(|kind| kind.wire_name() == value)
    }
}

/// Closed artifact-kind registry in stable wire order.
pub const ALL_ARTIFACT_KINDS: [ArtifactKind; 45] = [
    ArtifactKind::EditionV1,
    ArtifactKind::ChangeSetV1,
    ArtifactKind::ContextPackV1,
    ArtifactKind::ValidationResultsV1,
    ArtifactKind::KnownStateV1,
    ArtifactKind::SchemaVersionV1,
    ArtifactKind::EditBatchV1,
    ArtifactKind::OperationEffectV1,
    ArtifactKind::SchemaSetV1,
    ArtifactKind::ObjectRevisionV1,
    ArtifactKind::ObjectSetV1,
    ArtifactKind::EnvironmentConfigV1,
    ArtifactKind::ReleaseV1,
    ArtifactKind::ProofEnvelopeV1,
    ArtifactKind::DelegationV1,
    ArtifactKind::PrincipalRegistrationV1,
    ArtifactKind::AuthorizationDecisionV1,
    ArtifactKind::PolicyBundleV1,
    ArtifactKind::CommandV1,
    ArtifactKind::AuthenticatedCommandEnvelopeV1,
    ArtifactKind::BindingEnrollmentChallengeV1,
    ArtifactKind::BindingEnrollmentEnvelopeV1,
    ArtifactKind::AuthenticatedSubjectCommitmentV1,
    ArtifactKind::AuthenticatedActorContextV1,
    ArtifactKind::AuthorityRecordV1,
    ArtifactKind::AuthorityRecordEnvelopeV1,
    ArtifactKind::ContentResourceIntentV1,
    ArtifactKind::ContextPackV2,
    ArtifactKind::EditBatchV2,
    ArtifactKind::EditV2,
    ArtifactKind::ChangeSetV2,
    ArtifactKind::ValidationResultsV2,
    ArtifactKind::ObjectLocaleRevisionV1,
    ArtifactKind::ObjectSetV2,
    ArtifactKind::KnownStateV2,
    ArtifactKind::EditionV2,
    ArtifactKind::ReleaseV2,
    ArtifactKind::AuthorityEvidenceBundleV1,
    ArtifactKind::AuthenticatedLocalizedConsequenceV1,
    ArtifactKind::AuthenticatedSubjectOpeningV1,
    ArtifactKind::AuthorityCheckpointV1,
    ArtifactKind::VerificationTrustPolicyV1,
    ArtifactKind::VerificationReportV1,
    ArtifactKind::ReleaseSigningKeyV1,
    ArtifactKind::ReleaseSigningKeyRevocationV1,
];

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
        ArtifactKind, AuthorityRootTransitionId, BindingId, ChangeSetIntent, ChangeSetIntentError,
        ChangeSetStatus, ContentDigest, CorrelationId, DigestAlgorithm, DigestParseError,
        EnrollmentChallengeId, IdentifierError, LocaleId, LocaleRevision, LocaleRevisionError,
        ObjectId, ObjectLifecycleState, ObjectRevision, ObjectRevisionError, OperationId,
        PresentationId, PrincipalId, PrincipalType, RevocationId, SchemaId, SchemaIdError,
        SchemaVersion, SchemaVersionError, Timestamp, TimestampError,
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
    fn authority_operational_ids_share_the_uuid_v7_invariant() {
        assert!(UUID_V7.parse::<BindingId>().is_ok());
        assert!(UUID_V7.parse::<PresentationId>().is_ok());
        assert!(UUID_V7.parse::<EnrollmentChallengeId>().is_ok());
        assert!(UUID_V7.parse::<RevocationId>().is_ok());
        assert!(UUID_V7.parse::<AuthorityRootTransitionId>().is_ok());
        assert!(
            "550e8400-e29b-41d4-a716-446655440000"
                .parse::<BindingId>()
                .is_err()
        );
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
    fn locale_profile_is_exactly_cased_and_restricted() {
        for valid in [
            "en",
            "es-ES",
            "zh-Hant",
            "zh-Hant-TW",
            "de-1996",
            "en-US-posix",
            "sl-rozaj-biske",
        ] {
            assert_eq!(LocaleId::new(valid).unwrap().as_str(), valid);
        }
        for invalid in ["", "EN", "es-es", "zh-hant-TW", "e", "en-US-x", "en_US"] {
            assert!(LocaleId::new(invalid).is_err(), "accepted {invalid}");
        }
        assert_eq!(LocaleRevision::new(1).unwrap().get(), 1);
        assert_eq!(LocaleRevision::new(0).unwrap_err(), LocaleRevisionError);
    }

    #[test]
    fn localized_artifact_contexts_are_distinct() {
        let kinds = [
            ArtifactKind::ContentResourceIntentV1,
            ArtifactKind::ContextPackV2,
            ArtifactKind::EditV2,
            ArtifactKind::EditBatchV2,
            ArtifactKind::ChangeSetV2,
            ArtifactKind::ValidationResultsV2,
            ArtifactKind::ObjectLocaleRevisionV1,
            ArtifactKind::ObjectSetV2,
            ArtifactKind::KnownStateV2,
            ArtifactKind::EditionV2,
            ArtifactKind::ReleaseV2,
        ];
        let contexts = kinds
            .into_iter()
            .map(ArtifactKind::derive_key_context)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(contexts.len(), kinds.len());
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
        assert_eq!(
            ArtifactKind::OperationEffectV1.derive_key_context(),
            "proof:operation-effect:v1"
        );
    }

    #[test]
    fn authority_artifact_contexts_match_the_ratified_digest_registry() {
        let expected = [
            (ArtifactKind::CommandV1, "proof:command:v1"),
            (
                ArtifactKind::AuthenticatedCommandEnvelopeV1,
                "proof:authenticated-command-envelope:v1",
            ),
            (
                ArtifactKind::BindingEnrollmentChallengeV1,
                "proof:binding-enrollment-challenge:v1",
            ),
            (
                ArtifactKind::BindingEnrollmentEnvelopeV1,
                "proof:binding-enrollment-envelope:v1",
            ),
            (
                ArtifactKind::AuthenticatedSubjectCommitmentV1,
                "proof:authenticated-subject-commitment:v1",
            ),
            (
                ArtifactKind::AuthenticatedActorContextV1,
                "proof:authenticated-actor-context:v1",
            ),
            (ArtifactKind::AuthorityRecordV1, "proof:authority-record:v1"),
            (
                ArtifactKind::AuthorityRecordEnvelopeV1,
                "proof:authority-record-envelope:v1",
            ),
            (ArtifactKind::PolicyBundleV1, "proof:policy-bundle:v1"),
        ];
        let contexts = expected
            .into_iter()
            .map(|(kind, context)| {
                assert_eq!(kind.derive_key_context(), context);
                context
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(contexts.len(), expected.len());
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
