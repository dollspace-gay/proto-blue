//! AT Identifier (DID or Handle) validation and types.
//!
//! An AtIdentifier is either a DID or a Handle.

use std::fmt;
use std::str::FromStr;

use crate::did::Did;
use crate::handle::Handle;

/// A validated AT identifier (either a DID or a Handle).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AtIdentifier {
    /// A DID (e.g., `did:plc:asdf123`).
    Did(Did),
    /// A Handle (e.g., `alice.bsky.social`).
    Handle(Handle),
}

/// Error returned when an AT identifier string is invalid.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Invalid AT identifier: {reason}")]
pub struct InvalidAtIdentifierError {
    pub reason: String,
}

impl AtIdentifier {
    /// Create a new `AtIdentifier` from a string, attempting DID first, then Handle.
    pub fn new(s: &str) -> Result<Self, InvalidAtIdentifierError> {
        if s.starts_with("did:") {
            Did::new(s)
                .map(AtIdentifier::Did)
                .map_err(|e| InvalidAtIdentifierError {
                    reason: e.to_string(),
                })
        } else {
            Handle::new(s)
                .map(AtIdentifier::Handle)
                .map_err(|e| InvalidAtIdentifierError {
                    reason: e.to_string(),
                })
        }
    }

    /// Check whether a string is a valid AT identifier.
    pub fn is_valid(s: &str) -> bool {
        AtIdentifier::new(s).is_ok()
    }

    /// Return the inner string representation.
    pub fn as_str(&self) -> &str {
        match self {
            AtIdentifier::Did(d) => d.as_str(),
            AtIdentifier::Handle(h) => h.as_str(),
        }
    }

    /// Check if this is a DID.
    pub fn is_did(&self) -> bool {
        matches!(self, AtIdentifier::Did(_))
    }

    /// Check if this is a Handle.
    pub fn is_handle(&self) -> bool {
        matches!(self, AtIdentifier::Handle(_))
    }
}

impl fmt::Display for AtIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AtIdentifier::Did(d) => d.fmt(f),
            AtIdentifier::Handle(h) => h.fmt(f),
        }
    }
}

impl FromStr for AtIdentifier {
    type Err = InvalidAtIdentifierError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AtIdentifier::new(s)
    }
}

impl From<Did> for AtIdentifier {
    fn from(d: Did) -> Self {
        AtIdentifier::Did(d)
    }
}

impl From<Handle> for AtIdentifier {
    fn from(h: Handle) -> Self {
        AtIdentifier::Handle(h)
    }
}

impl serde::Serialize for AtIdentifier {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_str().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for AtIdentifier {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        AtIdentifier::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dids() {
        let id = AtIdentifier::new("did:plc:asdf123").unwrap();
        assert!(id.is_did());
        assert!(!id.is_handle());
    }

    #[test]
    fn parses_handles() {
        let id = AtIdentifier::new("alice.bsky.social").unwrap();
        assert!(id.is_handle());
        assert!(!id.is_did());
    }

    #[test]
    fn invalid() {
        assert!(AtIdentifier::new("").is_err());
        assert!(AtIdentifier::new("not-valid").is_err());
    }

    #[test]
    fn display() {
        let id = AtIdentifier::new("did:plc:asdf123").unwrap();
        assert_eq!(id.to_string(), "did:plc:asdf123");

        let id = AtIdentifier::new("alice.bsky.social").unwrap();
        assert_eq!(id.to_string(), "alice.bsky.social");
    }
}
