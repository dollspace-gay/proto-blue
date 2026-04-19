//! AT-URI validation and types.
//!
//! AT-URIs follow the format: `at://authority/collection/rkey`
//! See: <https://atproto.com/specs/at-uri-scheme>

use regex::Regex;
use std::fmt;
use std::str::FromStr;

use crate::did::Did;
use crate::handle::Handle;
use crate::nsid::Nsid;
use crate::recordkey::RecordKey;

/// Maximum length of an AT-URI (8 KiB).
const MAX_ATURI_LENGTH: usize = 8 * 1024;

// Case-sensitive by intent: the `at://` scheme is lowercase, DID methods
// are lowercase, and authority case is preserved for handles. The char
// classes already include both upper and lower where the spec allows
// mixed case (e.g. authority percent-encoding, rkeys); a global `(?i)`
// flag would weaken those constraints for no benefit. See issue #3.
static ATURI_REGEX: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(
        r"^at://(?P<authority>[a-zA-Z0-9._:%-]+)(/(?P<collection>[a-zA-Z0-9-.]+)(/(?P<rkey>[a-zA-Z0-9._~:@!$&%')(*+,;=-]+))?)?(#(?P<fragment>/[a-zA-Z0-9._~:@!$&%')(*+,;=\[\]/-]*))?$"
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

        Ok(Self {
            authority,
            collection,
            rkey,
            fragment,
        })
    }

    /// Check whether a string is a valid AT-URI.
    #[must_use]
    pub fn is_valid(s: &str) -> bool {
        Self::new(s).is_ok()
    }

    /// Build an AT-URI from individual parts. The collection and rkey
    /// are each optional, mirroring the TS `AtUri.make(host, coll?, rkey?)`
    /// constructor. Every part is validated in the same way as the
    /// full-string parser — calling `make(h, None, Some(r))` (rkey
    /// without collection) is an error.
    pub fn make(
        authority: &str,
        collection: Option<&str>,
        rkey: Option<&str>,
    ) -> Result<Self, InvalidAtUriError> {
        let mut s = format!("at://{authority}");
        if let Some(c) = collection {
            s.push('/');
            s.push_str(c);
            if let Some(r) = rkey {
                s.push('/');
                s.push_str(r);
            }
        } else if rkey.is_some() {
            return Err(InvalidAtUriError {
                reason: "AT-URI cannot have rkey without collection".to_string(),
            });
        }
        Self::new(&s)
    }

    /// Return the authority (DID or handle).
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Return the collection NSID, if present.
    #[must_use]
    pub fn collection(&self) -> Option<&str> {
        self.collection.as_deref()
    }

    /// Return the record key, if present.
    #[must_use]
    pub fn rkey(&self) -> Option<&str> {
        self.rkey.as_deref()
    }

    /// Return the fragment, if present.
    #[must_use]
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }

    /// The URI protocol — always `"at:"`.
    #[must_use]
    pub const fn protocol(&self) -> &'static str {
        "at:"
    }

    /// The URI origin — `at://<authority>`. Analogous to `URL.origin`
    /// in browsers (and to the TS `AtUri.origin` getter).
    #[must_use]
    pub fn origin(&self) -> String {
        format!("at://{}", self.authority)
    }

    /// Replace the authority. Validates the new value as a DID or a
    /// handle before committing — a failed update leaves the URI
    /// unchanged.
    pub fn set_authority(&mut self, v: impl Into<String>) -> Result<(), InvalidAtUriError> {
        let v = v.into();
        if v.starts_with("did:") {
            Did::new(&v).map_err(|e| InvalidAtUriError {
                reason: format!("Invalid DID authority: {e}"),
            })?;
        } else {
            Handle::new(&v).map_err(|e| InvalidAtUriError {
                reason: format!("Invalid handle authority: {e}"),
            })?;
        }
        self.authority = v;
        Ok(())
    }

    /// Replace the collection NSID. Pass `None` to clear both
    /// collection and rkey (an rkey without a collection is not a
    /// valid AT-URI, so setting collection to `None` also drops rkey).
    pub fn set_collection(&mut self, v: Option<&str>) -> Result<(), InvalidAtUriError> {
        if let Some(coll) = v {
            Nsid::new(coll).map_err(|e| InvalidAtUriError {
                reason: format!("Invalid collection NSID: {e}"),
            })?;
            self.collection = Some(coll.to_string());
        } else {
            self.collection = None;
            self.rkey = None;
        }
        Ok(())
    }

    /// Replace the record key. Setting a rkey on a URI with no
    /// collection is rejected — the spec requires `coll/rkey` together.
    pub fn set_rkey(&mut self, v: Option<&str>) -> Result<(), InvalidAtUriError> {
        match v {
            Some(rk) => {
                if self.collection.is_none() {
                    return Err(InvalidAtUriError {
                        reason: "cannot set rkey on an AT-URI that has no collection".to_string(),
                    });
                }
                RecordKey::new(rk).map_err(|e| InvalidAtUriError {
                    reason: format!("Invalid record key: {e}"),
                })?;
                self.rkey = Some(rk.to_string());
            }
            None => {
                self.rkey = None;
            }
        }
        Ok(())
    }

    /// Replace the fragment. Pass `None` to clear it. Fragments must
    /// start with `/` per the atproto syntax (they're JSON Pointer
    /// expressions), so a non-`None` value that doesn't is rejected.
    pub fn set_fragment(&mut self, v: Option<&str>) -> Result<(), InvalidAtUriError> {
        match v {
            Some(f) if !f.starts_with('/') => Err(InvalidAtUriError {
                reason: "AT-URI fragment must start with `/` (JSON Pointer)".to_string(),
            }),
            Some(f) => {
                // Round-trip through the parser to reuse its charset
                // checks — build a throwaway URI with just this
                // fragment and see if it parses.
                let probe = format!("at://{}#{}", self.authority, f);
                Self::new(&probe).map_err(|e| InvalidAtUriError {
                    reason: format!("Invalid fragment: {e}"),
                })?;
                self.fragment = Some(f.to_string());
                Ok(())
            }
            None => {
                self.fragment = None;
                Ok(())
            }
        }
    }

    /// Resolve a reference relative to this URI.
    ///
    /// Handles the two cases the atproto spec actually uses:
    ///
    /// - If `reference` is a full AT-URI (`at://…`), it's parsed in
    ///   isolation and returned.
    /// - If `reference` starts with `#`, the fragment is replaced.
    /// - Otherwise, `reference` is treated as a path applied to this
    ///   URI's authority: an empty / single-segment / two-segment
    ///   reference sets just the collection / collection + rkey.
    ///
    /// This is a pragmatic subset of TS's relative-URI handling —
    /// atproto doesn't use the full RFC 3986 scheme-relative / host-
    /// relative escalation ladder, so replicating all of it would be
    /// yak-shaving.
    pub fn resolve(&self, reference: &str) -> Result<Self, InvalidAtUriError> {
        if reference.starts_with("at://") {
            return Self::new(reference);
        }
        if let Some(frag) = reference.strip_prefix('#') {
            let mut cloned = self.clone();
            cloned.set_fragment(Some(&format!(
                "{}{frag}",
                if frag.starts_with('/') { "" } else { "/" }
            )))?;
            return Ok(cloned);
        }
        // Otherwise treat as `coll[/rkey][#frag]`.
        let (path_part, frag_part) = match reference.find('#') {
            Some(i) => (&reference[..i], Some(&reference[i + 1..])),
            None => (reference, None),
        };
        let parts: Vec<&str> = path_part.split('/').filter(|p| !p.is_empty()).collect();
        let mut cloned = self.clone();
        match parts.len() {
            0 => cloned.set_collection(None)?,
            1 => {
                cloned.set_collection(Some(parts[0]))?;
                cloned.set_rkey(None)?;
            }
            2 => {
                cloned.set_collection(Some(parts[0]))?;
                cloned.set_rkey(Some(parts[1]))?;
            }
            _ => {
                return Err(InvalidAtUriError {
                    reason: format!("relative reference has too many path segments: {reference:?}"),
                });
            }
        }
        cloned.set_fragment(
            frag_part
                .map(|f| {
                    if f.starts_with('/') {
                        f.to_string()
                    } else {
                        format!("/{f}")
                    }
                })
                .as_deref(),
        )?;
        Ok(cloned)
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
        Self::new(s)
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
        Self::new(&s).map_err(serde::de::Error::custom)
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

    /// Regression for issue #3: the AT-URI regex was globally case-insensitive
    /// (`(?i)`), so `AT://...` or `at://DID:plc:...` could slip through the
    /// regex even though `starts_with("at://")` and `Did::new` rejected them
    /// defensively. With `(?i)` removed, the regex itself now enforces
    /// lowercase `at://` and lowercase `did:` in the authority's method part.
    #[test]
    fn rejects_uppercase_scheme_via_regex() {
        assert!(AtUri::new("AT://did:plc:asdf123").is_err());
        assert!(AtUri::new("At://did:plc:asdf123").is_err());
        // Uppercase DID method is rejected by Did::new.
        assert!(AtUri::new("at://DID:plc:asdf123").is_err());
        assert!(AtUri::new("at://did:PLC:asdf123").is_err());
    }

    // ── make ─────────────────────────────────────────────────────────

    #[test]
    fn make_with_authority_only() {
        let uri = AtUri::make("alice.bsky.social", None, None).unwrap();
        assert_eq!(uri.to_string(), "at://alice.bsky.social");
        assert!(uri.collection().is_none());
        assert!(uri.rkey().is_none());
    }

    #[test]
    fn make_with_authority_and_collection() {
        let uri = AtUri::make("alice.bsky.social", Some("app.bsky.feed.post"), None).unwrap();
        assert_eq!(uri.to_string(), "at://alice.bsky.social/app.bsky.feed.post");
    }

    #[test]
    fn make_full() {
        let uri = AtUri::make(
            "did:plc:abc",
            Some("app.bsky.feed.post"),
            Some("3jui7kd54zh2y"),
        )
        .unwrap();
        assert_eq!(
            uri.to_string(),
            "at://did:plc:abc/app.bsky.feed.post/3jui7kd54zh2y"
        );
    }

    #[test]
    fn make_rkey_without_collection_is_error() {
        let err = AtUri::make("alice.bsky.social", None, Some("rec")).unwrap_err();
        assert!(err.reason.contains("rkey without collection"));
    }

    #[test]
    fn make_validates_each_part() {
        // Bad NSID.
        assert!(AtUri::make("alice.bsky.social", Some("not an nsid"), None).is_err());
        // Bad rkey.
        assert!(AtUri::make("alice.bsky.social", Some("app.bsky.feed.post"), Some(".")).is_err());
        // Bad authority.
        assert!(AtUri::make("not a handle", None, None).is_err());
    }

    // ── origin / protocol ─────────────────────────────────────────────

    #[test]
    fn origin_is_at_authority_only() {
        let uri = AtUri::new("at://did:plc:asdf123/app.bsky.feed.post/3jui7kd54zh2y").unwrap();
        assert_eq!(uri.origin(), "at://did:plc:asdf123");
        assert_eq!(uri.protocol(), "at:");
    }

    // ── setters ──────────────────────────────────────────────────────

    #[test]
    fn set_authority_accepts_valid_did_and_handle() {
        let mut uri = AtUri::new("at://alice.bsky.social/app.bsky.feed.post").unwrap();
        uri.set_authority("did:plc:abc").unwrap();
        assert_eq!(uri.authority(), "did:plc:abc");
        uri.set_authority("bob.example").unwrap();
        assert_eq!(uri.authority(), "bob.example");
    }

    #[test]
    fn set_authority_rejects_invalid_value_and_leaves_uri_unchanged() {
        let mut uri = AtUri::new("at://alice.bsky.social").unwrap();
        assert!(uri.set_authority("not an identifier").is_err());
        assert_eq!(uri.authority(), "alice.bsky.social");
    }

    #[test]
    fn set_collection_validates_nsid() {
        let mut uri = AtUri::new("at://alice.bsky.social").unwrap();
        uri.set_collection(Some("app.bsky.feed.post")).unwrap();
        assert_eq!(uri.collection(), Some("app.bsky.feed.post"));
        assert!(uri.set_collection(Some("not an nsid")).is_err());
        assert_eq!(uri.collection(), Some("app.bsky.feed.post"));
    }

    #[test]
    fn clearing_collection_also_clears_rkey() {
        let mut uri = AtUri::new("at://alice.bsky.social/app.bsky.feed.post/abc").unwrap();
        uri.set_collection(None).unwrap();
        assert!(uri.collection().is_none());
        assert!(uri.rkey().is_none());
    }

    #[test]
    fn set_rkey_requires_collection() {
        let mut uri = AtUri::new("at://alice.bsky.social").unwrap();
        let err = uri.set_rkey(Some("abc")).unwrap_err();
        assert!(err.reason.contains("no collection"));
    }

    #[test]
    fn set_rkey_validates_record_key() {
        let mut uri = AtUri::new("at://alice.bsky.social/app.bsky.feed.post/abc").unwrap();
        assert!(uri.set_rkey(Some(".")).is_err());
        // rkey unchanged after failed validation.
        assert_eq!(uri.rkey(), Some("abc"));
        uri.set_rkey(Some("def-123")).unwrap();
        assert_eq!(uri.rkey(), Some("def-123"));
        uri.set_rkey(None).unwrap();
        assert!(uri.rkey().is_none());
    }

    #[test]
    fn set_fragment_requires_leading_slash() {
        let mut uri = AtUri::new("at://alice.bsky.social").unwrap();
        assert!(uri.set_fragment(Some("no-slash")).is_err());
        uri.set_fragment(Some("/path/to/thing")).unwrap();
        assert_eq!(uri.fragment(), Some("/path/to/thing"));
        uri.set_fragment(None).unwrap();
        assert!(uri.fragment().is_none());
    }

    // ── resolve ──────────────────────────────────────────────────────

    #[test]
    fn resolve_absolute_uri_returns_that_uri() {
        let base = AtUri::new("at://alice.bsky.social").unwrap();
        let resolved = base
            .resolve("at://did:plc:abc/app.bsky.feed.post/xyz")
            .unwrap();
        assert_eq!(
            resolved.to_string(),
            "at://did:plc:abc/app.bsky.feed.post/xyz"
        );
    }

    #[test]
    fn resolve_fragment_keeps_authority_and_path() {
        let base = AtUri::new("at://alice.bsky.social/app.bsky.feed.post/abc").unwrap();
        let resolved = base.resolve("#/likeCount").unwrap();
        assert_eq!(
            resolved.to_string(),
            "at://alice.bsky.social/app.bsky.feed.post/abc#/likeCount"
        );
    }

    #[test]
    fn resolve_path_replaces_collection_and_rkey() {
        let base = AtUri::new("at://alice.bsky.social/foo.bar.baz/old").unwrap();
        let resolved = base.resolve("app.bsky.feed.post/new").unwrap();
        assert_eq!(
            resolved.to_string(),
            "at://alice.bsky.social/app.bsky.feed.post/new"
        );
    }

    #[test]
    fn resolve_single_segment_replaces_only_collection() {
        let base = AtUri::new("at://alice.bsky.social/foo.bar.baz/rec").unwrap();
        let resolved = base.resolve("app.bsky.feed.post").unwrap();
        // rkey cleared because we set_collection before set_rkey(None).
        assert_eq!(
            resolved.to_string(),
            "at://alice.bsky.social/app.bsky.feed.post"
        );
    }

    #[test]
    fn resolve_rejects_too_many_segments() {
        let base = AtUri::new("at://alice.bsky.social").unwrap();
        let err = base.resolve("a/b/c/d").unwrap_err();
        assert!(err.reason.contains("too many path segments"));
    }
}
