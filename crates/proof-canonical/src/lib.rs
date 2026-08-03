#![forbid(unsafe_code)]

//! Strict RFC 8785 canonicalization and domain-separated content digests.

use std::{collections::BTreeMap, fmt};

use proof_domain::{ArtifactKind, ContentDigest};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Number, Value};
use thiserror::Error;

/// Largest integer magnitude that interoperates exactly with IEEE-754 binary64.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Validated RFC 8785 canonical JSON bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalJson(String);

impl CanonicalJson {
    /// Returns the canonical UTF-8 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the canonical JSON as UTF-8 text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Strict JSON parsing or RFC 8785 canonicalization failed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CanonicalizationError {
    /// Input was not unambiguous I-JSON.
    #[error("invalid I-JSON input: {0}")]
    InvalidJson(String),
    /// An integer literal exceeded the interoperable exact range.
    #[error("integer `{0}` exceeds the interoperable exact range; encode it as a string")]
    UnsafeInteger(String),
    /// A validated JSON value could not be canonically serialized.
    #[error("RFC 8785 serialization failed: {0}")]
    Serialization(String),
}

/// Parses untrusted JSON without collapsing duplicate object keys.
///
/// # Errors
///
/// Returns [`CanonicalizationError::InvalidJson`] for malformed input,
/// duplicate object properties, invalid Unicode, or trailing data. Returns
/// [`CanonicalizationError::UnsafeInteger`] for integer literals outside the
/// exact interoperable range.
pub fn parse_strict(input: &[u8]) -> Result<Value, CanonicalizationError> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| CanonicalizationError::InvalidJson(error.to_string()))?
        .0;
    deserializer
        .end()
        .map_err(|error| CanonicalizationError::InvalidJson(error.to_string()))?;
    validate_safe_integers(&value)?;
    Ok(value)
}

/// Converts a JSON value to RFC 8785 canonical UTF-8 bytes.
///
/// # Errors
///
/// Returns [`CanonicalizationError::UnsafeInteger`] when an integer cannot be
/// represented exactly by interoperable JSON implementations. Returns
/// [`CanonicalizationError::Serialization`] if serialization fails.
pub fn canonicalize(value: &Value) -> Result<CanonicalJson, CanonicalizationError> {
    validate_safe_integers(value)?;
    serde_json_canonicalizer::to_string(value)
        .map(CanonicalJson)
        .map_err(|error| CanonicalizationError::Serialization(error.to_string()))
}

/// Strictly parses and canonically serializes untrusted JSON input.
///
/// # Errors
///
/// Returns a [`CanonicalizationError`] when the input is ambiguous, outside
/// the supported I-JSON profile, or cannot be serialized according to RFC 8785.
pub fn parse_and_canonicalize(input: &[u8]) -> Result<CanonicalJson, CanonicalizationError> {
    canonicalize(&parse_strict(input)?)
}

/// Computes an artifact-specific BLAKE3-256 digest of canonical JSON bytes.
#[must_use]
pub fn digest(kind: ArtifactKind, canonical: &CanonicalJson) -> ContentDigest {
    let mut hasher = blake3::Hasher::new_derive_key(kind.derive_key_context());
    hasher.update(canonical.as_bytes());
    ContentDigest::blake3(*hasher.finalize().as_bytes())
}

fn validate_safe_integers(value: &Value) -> Result<(), CanonicalizationError> {
    match value {
        Value::Array(values) => {
            for value in values {
                validate_safe_integers(value)?;
            }
        }
        Value::Object(properties) => {
            for value in properties.values() {
                validate_safe_integers(value)?;
            }
        }
        Value::Number(number) => validate_number(number)?,
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

fn validate_number(number: &Number) -> Result<(), CanonicalizationError> {
    if let Some(value) = number.as_u64() {
        if value > MAX_SAFE_INTEGER {
            return Err(CanonicalizationError::UnsafeInteger(number.to_string()));
        }
    } else if let Some(value) = number.as_i64()
        && value.unsigned_abs() > MAX_SAFE_INTEGER
    {
        return Err(CanonicalizationError::UnsafeInteger(number.to_string()));
    }
    Ok(())
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an unambiguous I-JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("NaN and Infinity are not valid I-JSON numbers"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut properties = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if properties.contains_key(&key) {
                return Err(de::Error::custom(format_args!(
                    "duplicate object property `{key}`"
                )));
            }
            let value = map.next_value::<StrictValue>()?;
            properties.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(properties.into_iter().collect())))
    }
}

#[cfg(test)]
mod tests {
    use proof_domain::{ArtifactKind, ContentDigest, OperationId};
    use serde::Deserialize;
    use serde_json::{Value, json};

    use super::{
        CanonicalizationError, MAX_SAFE_INTEGER, canonicalize, digest, parse_and_canonicalize,
        parse_strict,
    };

    #[test]
    fn object_properties_use_utf16_sort_order_recursively() {
        let input = json!({
            "\u{fb33}": "Hebrew Letter Dalet With Dagesh",
            "\u{1f600}": "Emoji: Grinning Face",
            "\u{20ac}": "Euro Sign"
        });

        let canonical = canonicalize(&input).unwrap();
        let dalet_with_dagesh = char::from_u32(0xfb33).unwrap();
        let expected = format!(
            "{{\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"{dalet_with_dagesh}\":\"Hebrew Letter Dalet With Dagesh\"}}"
        );

        assert_eq!(canonical.as_str(), expected);
    }

    #[test]
    fn duplicate_properties_fail_before_canonicalization() {
        let error = parse_strict(br#"{"outer":{"name":1,"name":2}}"#).unwrap_err();

        assert!(matches!(error, CanonicalizationError::InvalidJson(_)));
        assert!(
            error
                .to_string()
                .contains("duplicate object property `name`")
        );
    }

    #[test]
    fn unsafe_integer_literals_fail_closed() {
        let input = format!("{{\"unsafe\":{}}}", MAX_SAFE_INTEGER + 1);
        let error = parse_and_canonicalize(input.as_bytes()).unwrap_err();

        assert_eq!(
            error,
            CanonicalizationError::UnsafeInteger((MAX_SAFE_INTEGER + 1).to_string())
        );
    }

    #[test]
    fn artifact_types_are_cryptographically_separated() {
        let canonical = parse_and_canonicalize(br#"{"title":"Proof"}"#).unwrap();

        assert_ne!(
            digest(ArtifactKind::EditionV1, &canonical),
            digest(ArtifactKind::ChangeSetV1, &canonical)
        );
    }

    #[test]
    fn rfc8785_golden_vector_is_byte_exact_and_idempotent() {
        let input =
            include_bytes!("../../../conformance/v1/canonical-json/rfc8785-example.input.json");
        let canonical = parse_and_canonicalize(input).unwrap();
        let expected =
            include_str!("../../../conformance/v1/canonical-json/rfc8785-example.canonical.json")
                .trim_end();

        assert_eq!(canonical.as_str(), expected);
        assert_eq!(
            parse_and_canonicalize(canonical.as_bytes())
                .unwrap()
                .as_bytes(),
            canonical.as_bytes()
        );
    }

    #[test]
    fn domain_separated_digest_golden_vectors_are_stable() {
        let input =
            include_bytes!("../../../conformance/v1/canonical-json/rfc8785-example.input.json");
        let canonical = parse_and_canonicalize(input).unwrap();
        let vectors: DigestVectors = serde_json::from_slice(include_bytes!(
            "../../../conformance/v1/digests/rfc8785-example.json"
        ))
        .unwrap();

        assert_eq!(
            vectors.input,
            "../canonical-json/rfc8785-example.input.json"
        );
        for vector in vectors.vectors {
            let kind = match vector.artifact.as_str() {
                "edition-v1" => ArtifactKind::EditionV1,
                "changeset-v1" => ArtifactKind::ChangeSetV1,
                "context-pack-v1" => ArtifactKind::ContextPackV1,
                "validation-results-v1" => ArtifactKind::ValidationResultsV1,
                other => panic!("unsupported fixture artifact {other}"),
            };

            assert_eq!(kind.derive_key_context(), vector.context);
            assert_eq!(
                digest(kind, &canonical),
                vector.digest.parse::<ContentDigest>().unwrap()
            );
        }
    }

    #[test]
    fn uuidv7_conformance_vectors_are_portable() {
        let vectors: Value = serde_json::from_slice(include_bytes!(
            "../../../conformance/v1/identifiers/uuidv7.json"
        ))
        .unwrap();

        for valid in vectors["valid"].as_array().unwrap() {
            valid
                .as_str()
                .unwrap()
                .parse::<OperationId>()
                .expect("fixture value must be valid UUIDv7");
        }
        for invalid in vectors["invalid"].as_array().unwrap() {
            assert!(invalid.as_str().unwrap().parse::<OperationId>().is_err());
        }
    }

    #[derive(Deserialize)]
    struct DigestVectors {
        input: String,
        vectors: Vec<DigestVector>,
    }

    #[derive(Deserialize)]
    struct DigestVector {
        artifact: String,
        context: String,
        digest: String,
    }
}
