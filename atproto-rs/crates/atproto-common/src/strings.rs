//! String utility functions.

use unicode_segmentation::UnicodeSegmentation;

/// Count the number of grapheme clusters in a UTF-8 string.
///
/// This is the correct way to count "user-visible characters" for
/// AT Protocol text length validation (e.g., post character limits).
pub fn grapheme_len(s: &str) -> usize {
    s.graphemes(true).count()
}

/// Count the UTF-8 byte length of a string.
pub fn utf8_len(s: &str) -> usize {
    s.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_grapheme_len() {
        assert_eq!(grapheme_len("hello"), 5);
        assert_eq!(grapheme_len(""), 0);
    }

    #[test]
    fn emoji_grapheme_len() {
        // Single emoji = 1 grapheme cluster
        assert_eq!(grapheme_len("😀"), 1);
        // Family emoji (ZWJ sequence) = 1 grapheme cluster
        assert_eq!(grapheme_len("👨\u{200d}👩\u{200d}👧\u{200d}👧"), 1);
    }

    #[test]
    fn unicode_grapheme_len() {
        // é as combining sequence (e + combining acute) = 1 grapheme
        assert_eq!(grapheme_len("e\u{0301}"), 1);
        // Mixed content
        assert_eq!(grapheme_len("a~öñ©"), 5);
    }

    #[test]
    fn utf8_len_bytes() {
        assert_eq!(utf8_len("hello"), 5);
        assert_eq!(utf8_len("😀"), 4);
        assert_eq!(utf8_len(""), 0);
    }
}
