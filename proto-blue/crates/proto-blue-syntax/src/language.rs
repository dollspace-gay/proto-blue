//! BCP 47 language tag validation.
//!
//! See: <https://www.rfc-editor.org/rfc/rfc5646>

use once_cell::sync::Lazy;
use regex::Regex;

static LANGUAGE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r"^(",
        // Grandfathered tags
        r"(?:",
        r"(?:en-GB-oed|i-ami|i-bnn|i-default|i-enochian|i-hak|i-klingon|i-lux|",
        r"i-mingo|i-navajo|i-pwn|i-tao|i-tay|i-tsu|sgn-BE-FR|sgn-BE-NL|sgn-CH-DE)",
        r"|(?:art-lojban|cel-gaulish|no-bok|no-nyn|zh-guoyu|zh-hakka|zh-min|zh-min-nan|zh-xiang)",
        r")",
        r"|",
        // Language tag
        r"(?:",
        // Primary language subtag
        r"(?:[A-Za-z]{2,3}(?:-[A-Za-z]{3}(?:-[A-Za-z]{3}){0,2})?)",
        r"|[A-Za-z]{4}",
        r"|[A-Za-z]{5,8}",
        r")",
        // Script
        r"(?:-[A-Za-z]{4})?",
        // Region
        r"(?:-(?:[A-Za-z]{2}|[0-9]{3}))?",
        // Variant
        r"(?:-(?:[A-Za-z0-9]{5,8}|[0-9][A-Za-z0-9]{3}))*",
        // Extension
        r"(?:-[0-9A-WY-Za-wy-z](?:-[A-Za-z0-9]{2,8})+)*",
        // Private use
        r"(?:-x(?:-[A-Za-z0-9]{1,8})+)?",
        r"|",
        // Private use only
        r"x(?:-[A-Za-z0-9]{1,8})+",
        r")$",
    ))
    .unwrap()
});

/// Check if a string is a valid BCP 47 language tag.
pub fn is_valid_language(s: &str) -> bool {
    LANGUAGE_REGEX.is_match(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_language_tags() {
        let cases = [
            "en",
            "en-US",
            "zh-Hant-TW",
            "de-DE-1996",
            "x-private",
            "i-klingon",
            "art-lojban",
            "en-GB-oed",
        ];
        for tag in &cases {
            assert!(is_valid_language(tag), "should be valid: {tag}");
        }
    }

    #[test]
    fn invalid_language_tags() {
        let cases = ["", "1", "a", "toolongsubtag123", "en-", "-en"];
        for tag in &cases {
            assert!(!is_valid_language(tag), "should be invalid: {tag}");
        }
    }
}
