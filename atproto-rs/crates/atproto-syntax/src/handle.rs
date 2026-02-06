//! Handle validation and types.
//!
//! Handles are domain-name-like identifiers (e.g., `alice.bsky.social`).
//! See: <https://atproto.com/specs/handle>

use once_cell::sync::Lazy;
use regex::Regex;
use std::fmt;
use std::str::FromStr;

/// Maximum length of a handle.
const MAX_HANDLE_LENGTH: usize = 253;

/// Maximum length of a single label (domain segment).
const MAX_LABEL_LENGTH: usize = 63;

/// The canonical invalid handle value.
pub const HANDLE_INVALID: &str = "handle.invalid";

/// TLDs that are disallowed for handles.
pub const DISALLOWED_TLDS: &[&str] = &[
    ".local",
    ".arpa",
    ".invalid",
    ".localhost",
    ".internal",
    ".example",
    ".alt",
    ".onion",
];

static HANDLE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$",
    )
    .unwrap()
});

/// A validated AT Protocol handle.
///
/// Handles are domain-name-like identifiers such as `alice.bsky.social`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Handle(String);

/// Error returned when a handle string is invalid.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Invalid handle: {reason}")]
pub struct InvalidHandleError {
    pub reason: String,
}

impl Handle {
    /// Create a new `Handle` from a string, validating the format.
    pub fn new(s: &str) -> Result<Self, InvalidHandleError> {
        ensure_valid_handle(s)?;
        Ok(Handle(s.to_ascii_lowercase()))
    }

    /// Check whether a string is a valid handle without allocating.
    pub fn is_valid(s: &str) -> bool {
        ensure_valid_handle(s).is_ok()
    }

    /// Return the inner string (always lowercase).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Check if this is the canonical invalid handle.
    pub fn is_invalid_handle(&self) -> bool {
        self.0 == HANDLE_INVALID
    }
}

fn ensure_valid_handle(s: &str) -> Result<(), InvalidHandleError> {
    let err = |reason: &str| InvalidHandleError {
        reason: reason.to_string(),
    };

    if !s.is_ascii() {
        return Err(err("Handle must be ASCII"));
    }

    if s.len() > MAX_HANDLE_LENGTH {
        return Err(err(&format!(
            "Handle is too long ({} chars, max {})",
            s.len(),
            MAX_HANDLE_LENGTH
        )));
    }

    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return Err(err("Handle must have at least two parts separated by '.'"));
    }

    for label in &labels {
        if label.is_empty() {
            return Err(err("Handle labels must not be empty"));
        }
        if label.len() > MAX_LABEL_LENGTH {
            return Err(err(&format!(
                "Handle label too long ({} chars, max {})",
                label.len(),
                MAX_LABEL_LENGTH
            )));
        }
    }

    // TLD must start with a letter
    if let Some(tld) = labels.last() {
        if !tld.starts_with(|c: char| c.is_ascii_alphabetic()) {
            return Err(err("Handle TLD must start with an ASCII letter"));
        }
    }

    if !HANDLE_REGEX.is_match(s) {
        return Err(err("Handle contains invalid characters or format"));
    }

    Ok(())
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Handle {
    type Err = InvalidHandleError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Handle::new(s)
    }
}

impl AsRef<str> for Handle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl serde::Serialize for Handle {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Handle {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Handle::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_handles() {
        assert!(Handle::new("alice.bsky.social").is_ok());
        assert!(Handle::new("john.test").is_ok());
        assert!(Handle::new("a.b").is_ok());
        assert!(Handle::new("xn--nxasmq6b.com").is_ok());
        assert!(Handle::new("example.t").is_ok());
    }

    #[test]
    fn normalizes_to_lowercase() {
        let h = Handle::new("Alice.Bsky.Social").unwrap();
        assert_eq!(h.as_str(), "alice.bsky.social");
    }

    #[test]
    fn invalid_handles() {
        assert!(Handle::new("").is_err(), "empty");
        assert!(Handle::new("noperiod").is_err(), "no period");
        assert!(Handle::new(".leading-dot").is_err(), "leading dot");
        assert!(Handle::new("trailing-dot.").is_err(), "trailing dot");
        assert!(Handle::new("double..dot").is_err(), "double dot");
        assert!(
            Handle::new("-start.test").is_err(),
            "leading hyphen in label"
        );
        assert!(
            Handle::new("end-.test").is_err(),
            "trailing hyphen in label"
        );
        assert!(Handle::new("john.0test").is_err(), "TLD starts with digit");
        assert!(Handle::new("john.123").is_err(), "numeric TLD");
    }

    #[test]
    fn max_length() {
        let label = "a".repeat(63);
        // 63 + 1 + 63 + 1 + 63 + 1 + 63 = 255 > 253
        let long = format!("{label}.{label}.{label}.{label}");
        if long.len() > MAX_HANDLE_LENGTH {
            assert!(Handle::new(&long).is_err());
        }
    }

    #[test]
    fn serde_roundtrip() {
        let h = Handle::new("alice.bsky.social").unwrap();
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, "\"alice.bsky.social\"");
        let parsed: Handle = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, h);
    }
}
