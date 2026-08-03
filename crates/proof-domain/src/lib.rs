#![forbid(unsafe_code)]

//! Deterministic domain types for Proof.
//!
//! This crate is intentionally independent of interface, persistence, async,
//! network, and telemetry libraries.

use std::{fmt, str::FromStr};

use thiserror::Error;
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
        ArtifactKind, ContentDigest, CorrelationId, DigestAlgorithm, DigestParseError,
        IdentifierError, OperationId,
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
