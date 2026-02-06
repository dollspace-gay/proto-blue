//! DID (Decentralized Identifier) validation and types.
//!
//! DIDs follow the format: `did:method:method-specific-id`
//! See: <https://www.w3.org/TR/did-core/>

use once_cell::sync::Lazy;
use regex::Regex;
use std::fmt;
use std::str::FromStr;

/// Maximum length of a DID string.
const MAX_DID_LENGTH: usize = 2048;

static DID_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$").unwrap());

/// A validated DID (Decentralized Identifier).
///
/// Format: `did:method:method-specific-id`
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Did(String);

/// Error returned when a DID string is invalid.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Invalid DID: {reason}")]
pub struct InvalidDidError {
    pub reason: String,
}

impl Did {
    /// Create a new `Did` from a string, validating the format.
    pub fn new(s: &str) -> Result<Self, InvalidDidError> {
        ensure_valid_did(s)?;
        Ok(Did(s.to_string()))
    }

    /// Check whether a string is a valid DID without allocating.
    pub fn is_valid(s: &str) -> bool {
        ensure_valid_did(s).is_ok()
    }

    /// Return the DID method (e.g., `"plc"` for `did:plc:...`).
    pub fn method(&self) -> &str {
        // Safe: we validated the format in the constructor
        self.0.split(':').nth(1).unwrap()
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

fn ensure_valid_did(s: &str) -> Result<(), InvalidDidError> {
    let err = |reason: &str| InvalidDidError {
        reason: reason.to_string(),
    };

    if s.len() > MAX_DID_LENGTH {
        return Err(err(&format!(
            "DID is too long ({} chars, max {})",
            s.len(),
            MAX_DID_LENGTH
        )));
    }

    if !DID_REGEX.is_match(s) {
        // Provide more specific error messages
        if !s.starts_with("did:") {
            return Err(err("DID requires \"did:\" prefix"));
        }
        if s.ends_with(':') || s.ends_with('%') {
            return Err(err("DID cannot end with ':' or '%'"));
        }
        let parts: Vec<&str> = s.splitn(4, ':').collect();
        if parts.len() < 3 {
            return Err(err(
                "DID requires prefix, method, and method-specific content",
            ));
        }
        if parts[1].is_empty() || !parts[1].chars().all(|c| c.is_ascii_lowercase()) {
            return Err(err("DID method must be lowercase letters only"));
        }
        return Err(err("DID contains invalid characters"));
    }

    Ok(())
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Did {
    type Err = InvalidDidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Did::new(s)
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl serde::Serialize for Did {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Did {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Did::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_dids() {
        let cases = [
            "did:plc:asdf123",
            "did:web:example.com",
            "did:method:val:two",
            "did:m:v",
            "did:method:%3A",
            "did:method:val-two",
            "did:method:val_two",
            "did:method:val.two",
        ];
        for did in &cases {
            assert!(Did::new(did).is_ok(), "should be valid: {did}");
        }
    }

    #[test]
    fn invalid_dids() {
        let cases = [
            ("", "empty"),
            ("did:", "no method"),
            ("did:m:", "ends with colon"),
            ("did:m:%", "ends with percent"),
            ("DID:method:val", "uppercase prefix"),
            ("did:UPPER:val", "uppercase method"),
            ("did:m:v!v", "invalid character"),
            ("randomstring", "no prefix"),
            ("did:method:", "ends with colon"),
        ];
        for (input, desc) in &cases {
            assert!(
                Did::new(input).is_err(),
                "should be invalid ({desc}): {input}"
            );
        }
    }

    #[test]
    fn method_extraction() {
        let did = Did::new("did:plc:asdf123").unwrap();
        assert_eq!(did.method(), "plc");

        let did = Did::new("did:web:example.com").unwrap();
        assert_eq!(did.method(), "web");
    }

    #[test]
    fn serde_roundtrip() {
        let did = Did::new("did:plc:asdf123").unwrap();
        let json = serde_json::to_string(&did).unwrap();
        assert_eq!(json, "\"did:plc:asdf123\"");
        let parsed: Did = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, did);
    }

    #[test]
    fn max_length() {
        let long_did = format!("did:m:{}", "a".repeat(MAX_DID_LENGTH));
        assert!(Did::new(&long_did).is_err());
    }
}
