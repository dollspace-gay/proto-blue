//! AT-URI validation and types.
//!
//! AT-URIs follow the format: `at://authority/collection/rkey`
//! See: <https://atproto.com/specs/at-uri-scheme>

use once_cell::sync::Lazy;
use regex::Regex;
use std::fmt;
use std::str::FromStr;

use crate::did::Did;
use crate::handle::Handle;
use crate::nsid::Nsid;
use crate::recordkey::RecordKey;

/// Maximum length of an AT-URI (8 KiB).
const MAX_ATURI_LENGTH: usize = 8 * 1024;

static ATURI_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)^at://(?P<authority>[a-zA-Z0-9._:%-]+)(/(?P<collection>[a-zA-Z0-9-.]+)(/(?P<rkey>[a-zA-Z0-9._~:@!$&%')(*+,;=-]+))?)?(#(?P<fragment>/[a-zA-Z0-9._~:@!$&%')(*+,;=\[\]/-]*))?$"
    )
    .unwrap()
});

/// A validated AT-URI.
///
/// Format: `at://did-or-handle/collection/rkey`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AtUri {
    authority: String,
    collection: Option<String>,
    rkey: Option<String>,
    fragment: Option<String>,
}

/// Error returned when an AT-URI string is invalid.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Invalid AT-URI: {reason}")]
pub struct InvalidAtUriError {
    pub reason: String,
}

impl AtUri {
    /// Parse and validate an AT-URI string.
    pub fn new(s: &str) -> Result<Self, InvalidAtUriError> {
        let err = |reason: &str| InvalidAtUriError {
            reason: reason.to_string(),
        };

        if s.len() > MAX_ATURI_LENGTH {
            return Err(err(&format!(
                "AT-URI is too long ({} bytes, max {})",
                s.len(),
                MAX_ATURI_LENGTH
            )));
        }

        if !s.starts_with("at://") {
            return Err(err("AT-URI must start with \"at://\""));
        }

        let caps = ATURI_REGEX
            .captures(s)
            .ok_or_else(|| err("AT-URI format is invalid"))?;

        let authority = caps
            .name("authority")
            .ok_or_else(|| err("AT-URI missing authority"))?
            .as_str()
            .to_string();

        // Validate authority is a valid DID or handle
        if authority.starts_with("did:") {
            Did::new(&authority).map_err(|e| err(&format!("Invalid DID in AT-URI: {e}")))?;
        } else {
            Handle::new(&authority).map_err(|e| err(&format!("Invalid handle in AT-URI: {e}")))?;
        }

        let collection = caps.name("collection").map(|m| m.as_str().to_string());
        let rkey = caps.name("rkey").map(|m| m.as_str().to_string());
        let fragment = caps.name("fragment").map(|m| m.as_str().to_string());

        // If collection is present, validate it's a valid NSID
        if let Some(ref coll) = collection {
            Nsid::new(coll).map_err(|e| err(&format!("Invalid collection NSID in AT-URI: {e}")))?;
        }

        // If rkey is present, validate it
        if let Some(ref rk) = rkey {
            RecordKey::new(rk).map_err(|e| err(&format!("Invalid record key in AT-URI: {e}")))?;
        }

        // Can't have rkey without collection
        if rkey.is_some() && collection.is_none() {
            return Err(err("AT-URI cannot have rkey without collection"));
        }

        Ok(AtUri {
            authority,
            collection,
            rkey,
            fragment,
        })
    }

    /// Check whether a string is a valid AT-URI.
    pub fn is_valid(s: &str) -> bool {
        AtUri::new(s).is_ok()
    }

    /// Return the authority (DID or handle).
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Return the collection NSID, if present.
    pub fn collection(&self) -> Option<&str> {
        self.collection.as_deref()
    }

    /// Return the record key, if present.
    pub fn rkey(&self) -> Option<&str> {
        self.rkey.as_deref()
    }

    /// Return the fragment, if present.
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }
}

impl fmt::Display for AtUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at://{}", self.authority)?;
        if let Some(ref coll) = self.collection {
            write!(f, "/{coll}")?;
            if let Some(ref rk) = self.rkey {
                write!(f, "/{rk}")?;
            }
        }
        if let Some(ref frag) = self.fragment {
            write!(f, "#{frag}")?;
        }
        Ok(())
    }
}

impl FromStr for AtUri {
    type Err = InvalidAtUriError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AtUri::new(s)
    }
}

impl serde::Serialize for AtUri {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for AtUri {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        AtUri::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_aturis() {
        let cases = [
            "at://did:plc:asdf123/app.bsky.feed.post/3jui7kd54zh2y",
            "at://did:plc:asdf123/app.bsky.feed.post",
            "at://did:plc:asdf123",
            "at://alice.bsky.social/app.bsky.feed.post/3jui7kd54zh2y",
            "at://alice.bsky.social",
        ];
        for uri in &cases {
            assert!(AtUri::new(uri).is_ok(), "should be valid: {uri}");
        }
    }

    #[test]
    fn invalid_aturis() {
        assert!(AtUri::new("").is_err());
        assert!(AtUri::new("http://example.com").is_err());
        assert!(AtUri::new("at://").is_err());
    }

    #[test]
    fn parse_components() {
        let uri = AtUri::new("at://did:plc:asdf123/app.bsky.feed.post/3jui7kd54zh2y").unwrap();
        assert_eq!(uri.authority(), "did:plc:asdf123");
        assert_eq!(uri.collection(), Some("app.bsky.feed.post"));
        assert_eq!(uri.rkey(), Some("3jui7kd54zh2y"));
    }

    #[test]
    fn display_roundtrip() {
        let input = "at://did:plc:asdf123/app.bsky.feed.post/3jui7kd54zh2y";
        let uri = AtUri::new(input).unwrap();
        assert_eq!(uri.to_string(), input);
    }
}
