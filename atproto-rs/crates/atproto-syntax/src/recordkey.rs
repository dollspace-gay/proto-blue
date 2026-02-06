//! Record Key validation and types.
//!
//! Record keys are path-safe identifiers used in AT-URIs.
//! See: <https://atproto.com/specs/record-key>

use once_cell::sync::Lazy;
use regex::Regex;
use std::fmt;
use std::str::FromStr;

/// Maximum length of a record key.
const RECORD_KEY_MAX_LENGTH: usize = 512;

static RECORD_KEY_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_~.:\-]{1,512}$").unwrap());

/// A validated record key.
///
/// Record keys are 1-512 character strings from the set `[a-zA-Z0-9_~.:-]`,
/// and cannot be exactly `"."` or `".."`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordKey(String);

/// Error returned when a record key string is invalid.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Invalid record key: {reason}")]
pub struct InvalidRecordKeyError {
    pub reason: String,
}

impl RecordKey {
    /// Create a new `RecordKey` from a string, validating the format.
    pub fn new(s: &str) -> Result<Self, InvalidRecordKeyError> {
        ensure_valid_record_key(s)?;
        Ok(RecordKey(s.to_string()))
    }

    /// Check whether a string is a valid record key.
    pub fn is_valid(s: &str) -> bool {
        ensure_valid_record_key(s).is_ok()
    }

    /// Return the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

fn ensure_valid_record_key(s: &str) -> Result<(), InvalidRecordKeyError> {
    let err = |reason: &str| InvalidRecordKeyError {
        reason: reason.to_string(),
    };

    if s.is_empty() {
        return Err(err("Record key must not be empty"));
    }

    if s.len() > RECORD_KEY_MAX_LENGTH {
        return Err(err(&format!(
            "Record key too long ({} chars, max {})",
            s.len(),
            RECORD_KEY_MAX_LENGTH
        )));
    }

    if s == "." || s == ".." {
        return Err(err("Record key cannot be \".\" or \"..\""));
    }

    if !RECORD_KEY_REGEX.is_match(s) {
        return Err(err(
            "Record key must contain only [a-zA-Z0-9_~.:-] characters",
        ));
    }

    Ok(())
}

impl fmt::Display for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RecordKey {
    type Err = InvalidRecordKeyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RecordKey::new(s)
    }
}

impl AsRef<str> for RecordKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl serde::Serialize for RecordKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for RecordKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        RecordKey::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_record_keys() {
        let cases = ["self", "3jui7kd54zh2y", "example.com", "a", "a-b_c~d:e"];
        for rkey in &cases {
            assert!(RecordKey::new(rkey).is_ok(), "should be valid: {rkey}");
        }
    }

    #[test]
    fn invalid_record_keys() {
        assert!(RecordKey::new("").is_err(), "empty");
        assert!(RecordKey::new(".").is_err(), "dot");
        assert!(RecordKey::new("..").is_err(), "double dot");
        assert!(RecordKey::new("has space").is_err(), "space");
        assert!(RecordKey::new("has/slash").is_err(), "slash");
        assert!(RecordKey::new("has#hash").is_err(), "hash");
    }

    #[test]
    fn max_length() {
        let max = "a".repeat(RECORD_KEY_MAX_LENGTH);
        assert!(RecordKey::new(&max).is_ok());
        let too_long = "a".repeat(RECORD_KEY_MAX_LENGTH + 1);
        assert!(RecordKey::new(&too_long).is_err());
    }
}
