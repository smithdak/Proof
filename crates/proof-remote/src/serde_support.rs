//! Internal serde adapters that round-trip [`proof_domain`] value types through
//! their canonical `Display`/`FromStr` string forms.
//!
//! The `proof-domain` value types (for example [`proof_domain::ContentDigest`],
//! [`proof_domain::Timestamp`], and the operational identifiers) intentionally
//! implement `Display` and `FromStr` rather than `serde`. These modules mirror
//! the exact adapters used by `proof-application` so that every remote payload
//! serializes to the same canonical string shapes as the closed Schemas.

/// Serializes a `Display` value as a string and parses it back with `FromStr`.
pub mod display_string {
    use std::{fmt, str::FromStr};

    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes the value through its canonical [`fmt::Display`] form.
    ///
    /// # Errors
    ///
    /// Propagates serializer failures from the underlying string serialization.
    pub fn serialize<T: fmt::Display, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    /// Deserializes a string and parses it with the value's [`FromStr`] impl.
    ///
    /// # Errors
    ///
    /// Returns a custom deserialization error when parsing fails.
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Serializes an `Option<Display>` value, writing `null` when absent.
pub mod optional_display_string {
    use std::{fmt, str::FromStr};

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serializes `Some` through [`fmt::Display`] and `None` as JSON `null`.
    ///
    /// # Errors
    ///
    /// Propagates serializer failures from the underlying string serialization.
    #[allow(
        clippy::ref_option,
        reason = "serde `with` modules require a shared-reference field signature"
    )]
    pub fn serialize<T: fmt::Display, S: Serializer>(
        value: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .as_ref()
            .map(ToString::to_string)
            .serialize(serializer)
    }

    /// Deserializes a nullable string and parses `Some` with [`FromStr`].
    ///
    /// # Errors
    ///
    /// Returns a custom deserialization error when parsing fails.
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|value| value.parse().map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// Serializes a slice of `Display` values as an ordered string array.
pub mod display_string_vec {
    use std::{fmt, str::FromStr};

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serializes each element through [`fmt::Display`].
    ///
    /// # Errors
    ///
    /// Propagates serializer failures from the underlying array serialization.
    pub fn serialize<T: fmt::Display, S: Serializer>(
        value: &[T],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    /// Deserializes a string array, parsing each element with [`FromStr`].
    ///
    /// # Errors
    ///
    /// Returns a custom deserialization error when any element fails to parse.
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
        D: Deserializer<'de>,
    {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|value| value.parse().map_err(serde::de::Error::custom))
            .collect()
    }
}
