use std::{collections::HashSet, fmt};

use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq)]
pub enum StrictJsonError {
    #[error("invalid unambiguous JSON: {0}")]
    Invalid(String),
    #[error("JSON input is not RFC 8785 canonical")]
    NonCanonical,
    #[error("JSON input exceeds the maximum nesting depth")]
    TooDeep,
    #[error("JSON input contains an unsafe integer")]
    UnsafeInteger,
}

pub fn parse_canonical(input: &[u8], max_depth: usize) -> Result<Value, StrictJsonError> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| StrictJsonError::Invalid(error.to_string()))?
        .0;
    deserializer
        .end()
        .map_err(|error| StrictJsonError::Invalid(error.to_string()))?;
    validate_value(&value, 1, max_depth)?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|error| StrictJsonError::Invalid(error.to_string()))?;
    if canonical != input {
        return Err(StrictJsonError::NonCanonical);
    }
    Ok(value)
}

pub fn canonical_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, StrictJsonError> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| StrictJsonError::Invalid(error.to_string()))
}

fn validate_value(value: &Value, depth: usize, max_depth: usize) -> Result<(), StrictJsonError> {
    if depth > max_depth {
        return Err(StrictJsonError::TooDeep);
    }
    match value {
        Value::Array(values) => {
            for value in values {
                validate_value(value, depth + 1, max_depth)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_value(value, depth + 1, max_depth)?;
            }
        }
        Value::Number(number) => validate_number(number)?,
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

fn validate_number(number: &Number) -> Result<(), StrictJsonError> {
    const MAX_SAFE: u64 = 9_007_199_254_740_991;
    if let Some(value) = number.as_u64() {
        if value > MAX_SAFE {
            return Err(StrictJsonError::UnsafeInteger);
        }
    } else if let Some(value) = number.as_i64()
        && value.unsigned_abs() > MAX_SAFE
    {
        return Err(StrictJsonError::UnsafeInteger);
    }
    Ok(())
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictValueVisitor).map(Self)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unambiguous I-JSON")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        StrictValue::deserialize(deserializer).map(|value| value.0)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = HashSet::new();
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate object member `{key}`"
                )));
            }
            let value = map.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicates_noncanonical_and_unsafe_integers() {
        assert!(matches!(
            parse_canonical(br#"{"a":1,"a":2}"#, 8),
            Err(StrictJsonError::Invalid(_))
        ));
        assert_eq!(
            parse_canonical(br#"{ "a": 1 }"#, 8),
            Err(StrictJsonError::NonCanonical)
        );
        assert_eq!(
            parse_canonical(br#"{"a":9007199254740992}"#, 8),
            Err(StrictJsonError::UnsafeInteger)
        );
    }
}
