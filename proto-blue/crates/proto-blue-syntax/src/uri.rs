//! Generic URI validation.
//!
//! The atproto lexicon `format: uri` constraint is deliberately loose
//! — it matches anything of the shape `<scheme>:<rest>` where
//! `<scheme>` starts with an ASCII letter and contains only
//! `[A-Za-z0-9+.-]`. Mirrors TS `@atproto/syntax::isValidUri`.

/// `true` when `s` parses as a minimally-valid URI — an RFC 3986
/// scheme followed by a colon and at least one further character.
///
/// Does *not* attempt full RFC 3986 parsing: atproto needs to match
/// `did:`, `at:`, `https:`, `mailto:`, `http:`, etc. without pulling
/// in a full URL parser at the syntax layer.
pub fn is_valid_uri(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    if scheme.is_empty() || rest.is_empty() {
        return false;
    }
    let mut chars = scheme.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_schemes() {
        assert!(is_valid_uri("https://example.com/path"));
        assert!(is_valid_uri("http://localhost:8080"));
        assert!(is_valid_uri("at://did:plc:x/col/key"));
        assert!(is_valid_uri("did:plc:abc"));
        assert!(is_valid_uri("mailto:user@example.com"));
        assert!(is_valid_uri("urn:isbn:0451450523"));
    }

    #[test]
    fn rejects_malformed() {
        assert!(!is_valid_uri(""));
        assert!(!is_valid_uri("not-a-uri"));
        assert!(!is_valid_uri("://missing-scheme"));
        assert!(!is_valid_uri(":missing-scheme"));
        assert!(!is_valid_uri("1http://starts-with-digit"));
        assert!(!is_valid_uri("http:"));
    }
}
