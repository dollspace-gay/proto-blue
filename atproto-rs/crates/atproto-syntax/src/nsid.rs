//! NSID (Namespaced Identifier) validation and types.
//!
//! NSIDs are reverse-DNS-style identifiers like `com.atproto.repo.createRecord`.
//! See: <https://atproto.com/specs/nsid>

use once_cell::sync::Lazy;
use regex::Regex;
use std::fmt;
use std::str::FromStr;

/// Maximum length of an NSID string (253 domain + 1 dot + 63 name).
const MAX_NSID_LENGTH: usize = 317;

/// Maximum length of a single segment.
const MAX_SEGMENT_LENGTH: usize = 63;

/// Minimum number of segments (authority has at least 2 + name = 3).
const MIN_SEGMENTS: usize = 3;

static NSID_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+(?:\.[a-zA-Z](?:[a-zA-Z0-9]{0,62})?)$",
    )
    .unwrap()
});

/// A validated NSID (Namespaced Identifier).
///
/// Format: `authority.name` where authority is reversed domain (e.g., `com.atproto.repo.createRecord`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Nsid(String);

/// Error returned when an NSID string is invalid.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Invalid NSID: {reason}")]
pub struct InvalidNsidError {
    pub reason: String,
}

impl Nsid {
    /// Create a new `Nsid` from a string, validating the format.
    pub fn new(s: &str) -> Result<Self, InvalidNsidError> {
        ensure_valid_nsid(s)?;
        Ok(Nsid(s.to_string()))
    }

    /// Check whether a string is a valid NSID.
    pub fn is_valid(s: &str) -> bool {
        ensure_valid_nsid(s).is_ok()
    }

    /// Return the authority portion (all segments except the last).
    ///
    /// For `com.atproto.repo.createRecord`, returns `com.atproto.repo`.
    pub fn authority(&self) -> &str {
        let last_dot = self.0.rfind('.').unwrap();
        &self.0[..last_dot]
    }

    /// Return the name portion (last segment).
    ///
    /// For `com.atproto.repo.createRecord`, returns `createRecord`.
    pub fn name(&self) -> &str {
        let last_dot = self.0.rfind('.').unwrap();
        &self.0[last_dot + 1..]
    }

    /// Return the segments as a vector.
    pub fn segments(&self) -> Vec<&str> {
        self.0.split('.').collect()
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

fn ensure_valid_nsid(s: &str) -> Result<(), InvalidNsidError> {
    let err = |reason: &str| InvalidNsidError {
        reason: reason.to_string(),
    };

    if s.len() > MAX_NSID_LENGTH {
        return Err(err(&format!(
            "NSID is too long ({} chars, max {})",
            s.len(),
            MAX_NSID_LENGTH
        )));
    }

    if !s.is_ascii() {
        return Err(err("NSID must be ASCII only"));
    }

    let segments: Vec<&str> = s.split('.').collect();

    if segments.len() < MIN_SEGMENTS {
        return Err(err(&format!(
            "NSID must have at least {} segments, found {}",
            MIN_SEGMENTS,
            segments.len()
        )));
    }

    for segment in &segments {
        if segment.is_empty() {
            return Err(err("NSID segments must not be empty"));
        }
        if segment.len() > MAX_SEGMENT_LENGTH {
            return Err(err(&format!(
                "NSID segment too long ({} chars, max {})",
                segment.len(),
                MAX_SEGMENT_LENGTH
            )));
        }
    }

    // The last segment (name) must start with a letter, no hyphens
    if let Some(name) = segments.last() {
        if name.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(err("NSID name segment must not start with a digit"));
        }
        if name.contains('-') {
            return Err(err("NSID name segment must not contain hyphens"));
        }
    }

    // First segment must not start with a digit
    if let Some(first) = segments.first() {
        if first.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(err("NSID first segment must not start with a digit"));
        }
    }

    if !NSID_REGEX.is_match(s) {
        return Err(err("NSID format is invalid"));
    }

    Ok(())
}

impl fmt::Display for Nsid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Nsid {
    type Err = InvalidNsidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Nsid::new(s)
    }
}

impl AsRef<str> for Nsid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl serde::Serialize for Nsid {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Nsid {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Nsid::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_nsids() {
        let cases = [
            "com.atproto.repo.createRecord",
            "app.bsky.feed.post",
            "com.example.fooBar",
            "io.github.test",
            "a.b.c",
        ];
        for nsid in &cases {
            assert!(Nsid::new(nsid).is_ok(), "should be valid: {nsid}");
        }
    }

    #[test]
    fn invalid_nsids() {
        assert!(Nsid::new("").is_err(), "empty");
        assert!(Nsid::new("com.example").is_err(), "only 2 segments");
        assert!(
            Nsid::new("com.example.123").is_err(),
            "name starts with digit"
        );
        assert!(Nsid::new("com.example.foo-bar").is_err(), "name has hyphen");
        assert!(Nsid::new("com..example.test").is_err(), "empty segment");
    }

    #[test]
    fn authority_and_name() {
        let nsid = Nsid::new("com.atproto.repo.createRecord").unwrap();
        assert_eq!(nsid.authority(), "com.atproto.repo");
        assert_eq!(nsid.name(), "createRecord");
    }

    #[test]
    fn segments() {
        let nsid = Nsid::new("app.bsky.feed.post").unwrap();
        assert_eq!(nsid.segments(), vec!["app", "bsky", "feed", "post"]);
    }

    #[test]
    fn serde_roundtrip() {
        let nsid = Nsid::new("com.atproto.repo.createRecord").unwrap();
        let json = serde_json::to_string(&nsid).unwrap();
        let parsed: Nsid = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, nsid);
    }
}
