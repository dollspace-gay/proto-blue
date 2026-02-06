//! Mute word matching algorithm.
//!
//! Matches user-defined mute words against post text and tags,
//! with language-aware word boundary detection and punctuation handling.

use super::types::MutedWord;

/// Languages that use substring matching instead of word boundaries.
const SUBSTRING_LANGUAGES: &[&str] = &["ja", "zh", "ko", "th", "vi"];

/// Check if any muted words match the given text, facets, and tags.
///
/// Returns the list of matching muted words, or empty vec if none match.
pub fn check_muted_words(
    muted_words: &[MutedWord],
    text: &str,
    tags: &[String],
    languages: &[String],
    is_following_author: bool,
) -> Vec<MutedWordMatch> {
    let now = chrono::Utc::now().to_rfc3339();
    let text_lower = text.to_lowercase();
    let tags_lower: Vec<String> = tags.iter().map(|t| t.to_lowercase()).collect();
    let use_substring = languages
        .iter()
        .any(|lang| SUBSTRING_LANGUAGES.contains(&lang.as_str()));

    let mut matches = Vec::new();

    for word in muted_words {
        // Check expiration
        if let Some(ref expires) = word.expires_at {
            if expires.as_str() < now.as_str() {
                continue;
            }
        }

        // Check actor target exclusion
        if word.actor_target.as_deref() == Some("exclude-following") && is_following_author {
            continue;
        }

        let muted_lower = word.value.to_lowercase();

        // Tag matching (always applies regardless of targets)
        if tags_lower.contains(&muted_lower) {
            matches.push(MutedWordMatch {
                word: word.clone(),
                predicate: muted_lower.clone(),
            });
            continue;
        }

        // Content text matching (only if targets includes "content")
        if !word.targets.contains(&"content".to_string()) {
            continue;
        }

        if let Some(predicate) = match_text(&text_lower, &muted_lower, use_substring) {
            matches.push(MutedWordMatch {
                word: word.clone(),
                predicate,
            });
        }
    }

    matches
}

/// Match a muted word against text content.
fn match_text(text: &str, muted: &str, use_substring: bool) -> Option<String> {
    if muted.is_empty() || text.is_empty() {
        return None;
    }

    // Single character or substring language: use simple contains
    if muted.chars().count() == 1 || use_substring {
        if text.contains(muted) {
            return Some(muted.to_string());
        }
        return None;
    }

    // Too long to match
    if muted.len() > text.len() {
        return None;
    }

    // Exact match
    if muted == text {
        return Some(muted.to_string());
    }

    // Phrase with spaces or punctuation: use simple contains
    if has_space_or_punctuation(muted) && text.contains(muted) {
        return Some(muted.to_string());
    }

    // Word-by-word matching with boundary detection
    match_by_words(text, muted)
}

/// Word-by-word matching with punctuation handling.
fn match_by_words(text: &str, muted: &str) -> Option<String> {
    for word in text.split_whitespace() {
        // Exact word match
        if word == muted {
            return Some(word.to_string());
        }

        // Strip leading/trailing punctuation
        let trimmed = trim_punctuation(word);
        if trimmed == muted {
            return Some(trimmed.to_string());
        }

        // If the trimmed word still contains internal punctuation
        if trimmed.chars().any(is_punctuation) {
            // Escape case: skip words containing slashes (URLs, paths)
            if trimmed.contains('/') {
                continue;
            }

            // Replace all punctuation with spaces
            let spaced: String = trimmed
                .chars()
                .map(|c| if is_punctuation(c) { ' ' } else { c })
                .collect();
            if spaced == muted {
                return Some(trimmed.to_string());
            }

            // Remove all spaces from spaced version (contiguous)
            let contiguous: String = spaced.chars().filter(|c| *c != ' ').collect();
            if contiguous == muted {
                return Some(trimmed.to_string());
            }

            // Split by punctuation and check each part
            let parts: Vec<&str> = trimmed
                .split(|c: char| is_punctuation(c))
                .filter(|s| !s.is_empty())
                .collect();
            for part in &parts {
                if *part == muted {
                    return Some((*part).to_string());
                }
            }
        }
    }
    None
}

/// Check if a string contains spaces or punctuation.
fn has_space_or_punctuation(s: &str) -> bool {
    s.chars().any(|c| c.is_whitespace() || is_punctuation(c))
}

/// Check if a character is Unicode punctuation.
fn is_punctuation(c: char) -> bool {
    // Unicode general category P (punctuation)
    matches!(
        c.general_category_group(),
        UnicodeGeneralCategoryGroup::Punctuation
    ) || matches!(
        c,
        '!' | '@'
            | '#'
            | '$'
            | '%'
            | '^'
            | '&'
            | '*'
            | '('
            | ')'
            | '-'
            | '_'
            | '='
            | '+'
            | '['
            | ']'
            | '{'
            | '}'
            | '|'
            | '\\'
            | ';'
            | ':'
            | '\''
            | '"'
            | ','
            | '.'
            | '<'
            | '>'
            | '/'
            | '?'
            | '~'
            | '`'
    )
}

/// Trim leading and trailing punctuation from a word.
fn trim_punctuation(word: &str) -> &str {
    let start = word
        .char_indices()
        .find(|(_, c)| !is_punctuation(*c))
        .map(|(i, _)| i)
        .unwrap_or(word.len());
    let end = word
        .char_indices()
        .rev()
        .find(|(_, c)| !is_punctuation(*c))
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    if start >= end { "" } else { &word[start..end] }
}

/// Unicode general category group helper.
/// Rust's char doesn't have a built-in general_category_group(), so we check manually.
trait UnicodeCategory {
    fn general_category_group(&self) -> UnicodeGeneralCategoryGroup;
}

#[derive(PartialEq)]
enum UnicodeGeneralCategoryGroup {
    Punctuation,
    Other,
}

impl UnicodeCategory for char {
    fn general_category_group(&self) -> UnicodeGeneralCategoryGroup {
        // Check common Unicode punctuation ranges
        if self.is_ascii_punctuation() {
            return UnicodeGeneralCategoryGroup::Punctuation;
        }
        // Unicode general category Pc, Pd, Pe, Pf, Pi, Po, Ps
        match *self {
            '\u{00A1}'..='\u{00BF}' => UnicodeGeneralCategoryGroup::Punctuation, // Latin-1 punct
            '\u{2010}'..='\u{2027}' => UnicodeGeneralCategoryGroup::Punctuation, // General punct
            '\u{2030}'..='\u{205E}' => UnicodeGeneralCategoryGroup::Punctuation, // General punct
            '\u{2E00}'..='\u{2E52}' => UnicodeGeneralCategoryGroup::Punctuation, // Supplemental punct
            '\u{3001}'..='\u{3003}' => UnicodeGeneralCategoryGroup::Punctuation, // CJK punct
            '\u{FE50}'..='\u{FE6B}' => UnicodeGeneralCategoryGroup::Punctuation, // Small forms
            '\u{FF01}'..='\u{FF0F}' => UnicodeGeneralCategoryGroup::Punctuation, // Fullwidth punct
            '\u{FF1A}'..='\u{FF20}' => UnicodeGeneralCategoryGroup::Punctuation, // Fullwidth punct
            _ => UnicodeGeneralCategoryGroup::Other,
        }
    }
}

/// A match result from mute word checking.
#[derive(Debug, Clone)]
pub struct MutedWordMatch {
    pub word: MutedWord,
    pub predicate: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn muted(value: &str) -> MutedWord {
        MutedWord {
            value: value.into(),
            targets: vec!["content".into()],
            actor_target: None,
            expires_at: None,
        }
    }

    fn muted_tag(value: &str) -> MutedWord {
        MutedWord {
            value: value.into(),
            targets: vec!["tag".into()],
            actor_target: None,
            expires_at: None,
        }
    }

    fn check(words: &[MutedWord], text: &str) -> Vec<MutedWordMatch> {
        check_muted_words(words, text, &[], &[], false)
    }

    fn check_with_tags(words: &[MutedWord], text: &str, tags: &[&str]) -> Vec<MutedWordMatch> {
        let tags: Vec<String> = tags.iter().map(|s| s.to_string()).collect();
        check_muted_words(words, text, &tags, &[], false)
    }

    fn check_with_langs(words: &[MutedWord], text: &str, langs: &[&str]) -> Vec<MutedWordMatch> {
        let langs: Vec<String> = langs.iter().map(|s| s.to_string()).collect();
        check_muted_words(words, text, &[], &langs, false)
    }

    #[test]
    fn exact_word_match() {
        let words = [muted("test")];
        assert_eq!(check(&words, "this is a test post").len(), 1);
        assert_eq!(check(&words, "no match here").len(), 0);
    }

    #[test]
    fn case_insensitive() {
        let words = [muted("Test")];
        assert_eq!(check(&words, "this is a test").len(), 1);
        assert_eq!(check(&words, "this is a TEST").len(), 1);
    }

    #[test]
    fn exact_full_text_match() {
        let words = [muted("test")];
        assert_eq!(check(&words, "test").len(), 1);
    }

    #[test]
    fn tag_matching() {
        let words = [muted_tag("politics")];
        assert_eq!(
            check_with_tags(&words, "nice weather", &["politics"]).len(),
            1
        );
        assert_eq!(
            check_with_tags(&words, "nice weather", &["sports"]).len(),
            0
        );
    }

    #[test]
    fn tag_matching_case_insensitive() {
        let words = [muted_tag("Politics")];
        assert_eq!(check_with_tags(&words, "", &["politics"]).len(), 1);
        assert_eq!(check_with_tags(&words, "", &["POLITICS"]).len(), 1);
    }

    #[test]
    fn punctuation_trailing() {
        let words = [muted("yay")];
        assert_eq!(check(&words, "yay!").len(), 1);
        assert_eq!(check(&words, "yay!!!").len(), 1);
    }

    #[test]
    fn punctuation_leading() {
        let words = [muted("test")];
        assert_eq!(check(&words, "...test").len(), 1);
    }

    #[test]
    fn apostrophe_handling() {
        let words = [muted("bluesky")];
        assert_eq!(check(&words, "Bluesky's cool").len(), 1);
    }

    #[test]
    fn hyphen_splitting() {
        let words = [muted("bad")];
        assert_eq!(check(&words, "super-bad movie").len(), 1);
    }

    #[test]
    fn underscore_as_space() {
        let words = [muted("idk what this")];
        assert_eq!(check(&words, "idk_what_this is").len(), 1);
    }

    #[test]
    fn slash_in_word_skipped() {
        let words = [muted("and")];
        // Words containing slashes are skipped to avoid matching parts of URLs
        assert_eq!(check(&words, "and/or").len(), 0);
    }

    #[test]
    fn phrase_with_spaces() {
        let words = [muted("bad word")];
        assert_eq!(check(&words, "this is a bad word in context").len(), 1);
        assert_eq!(check(&words, "badword").len(), 0);
    }

    #[test]
    fn single_character_match() {
        let words = [muted("X")];
        assert_eq!(check(&words, "check x marks").len(), 1);
    }

    #[test]
    fn cjk_substring_matching() {
        let words = [muted("テスト")];
        assert_eq!(
            check_with_langs(&words, "これはテストです", &["ja"]).len(),
            1
        );
    }

    #[test]
    fn expired_word_skipped() {
        let words = [MutedWord {
            value: "test".into(),
            targets: vec!["content".into()],
            actor_target: None,
            expires_at: Some("2020-01-01T00:00:00Z".into()),
        }];
        assert_eq!(check(&words, "this is a test").len(), 0);
    }

    #[test]
    fn exclude_following_when_following() {
        let words = [MutedWord {
            value: "test".into(),
            targets: vec!["content".into()],
            actor_target: Some("exclude-following".into()),
            expires_at: None,
        }];
        let result = check_muted_words(&words, "this is a test", &[], &[], true);
        assert_eq!(result.len(), 0);
        let result = check_muted_words(&words, "this is a test", &[], &[], false);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn empty_text_no_match() {
        let words = [muted("test")];
        assert_eq!(check(&words, "").len(), 0);
    }

    #[test]
    fn muted_word_longer_than_text() {
        let words = [muted("very long muted word phrase")];
        assert_eq!(check(&words, "short").len(), 0);
    }

    #[test]
    fn multiple_matches() {
        let words = [muted("foo"), muted("bar")];
        assert_eq!(check(&words, "foo and bar").len(), 2);
    }

    #[test]
    fn trim_punctuation_basic() {
        assert_eq!(trim_punctuation("hello"), "hello");
        assert_eq!(trim_punctuation("!hello!"), "hello");
        assert_eq!(trim_punctuation("...test..."), "test");
        assert_eq!(trim_punctuation("!!!"), "");
    }
}
