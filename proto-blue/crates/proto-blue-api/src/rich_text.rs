//! Rich text with facet annotations (mentions, links, tags).
//!
//! Facets use UTF-8 byte offsets, which align naturally with Rust's `&str`.

use regex::Regex;
use std::sync::LazyLock;
use unicode_segmentation::UnicodeSegmentation;

/// A facet annotation on a sub-string of rich text.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Facet {
    pub index: ByteSlice,
    pub features: Vec<FacetFeature>,
}

/// UTF-8 byte range [start, end).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ByteSlice {
    pub byte_start: usize,
    pub byte_end: usize,
}

/// A facet feature — what kind of annotation this is.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "$type")]
pub enum FacetFeature {
    #[serde(rename = "app.bsky.richtext.facet#mention")]
    Mention { did: String },
    #[serde(rename = "app.bsky.richtext.facet#link")]
    Link { uri: String },
    #[serde(rename = "app.bsky.richtext.facet#tag")]
    Tag { tag: String },
}

/// A segment of rich text — either plain or annotated.
#[derive(Debug, Clone)]
pub struct RichTextSegment {
    pub text: String,
    pub facet: Option<Facet>,
}

impl RichTextSegment {
    pub fn is_mention(&self) -> bool {
        self.facet.as_ref().is_some_and(|f| {
            f.features
                .iter()
                .any(|feat| matches!(feat, FacetFeature::Mention { .. }))
        })
    }

    pub fn is_link(&self) -> bool {
        self.facet.as_ref().is_some_and(|f| {
            f.features
                .iter()
                .any(|feat| matches!(feat, FacetFeature::Link { .. }))
        })
    }

    pub fn is_tag(&self) -> bool {
        self.facet.as_ref().is_some_and(|f| {
            f.features
                .iter()
                .any(|feat| matches!(feat, FacetFeature::Tag { .. }))
        })
    }
}

/// Rich text with facet annotations.
///
/// Text is stored as a UTF-8 string. Facet indices are UTF-8 byte offsets,
/// which is Rust's native string indexing — no conversion needed.
#[derive(Debug, Clone)]
pub struct RichText {
    text: String,
    facets: Vec<Facet>,
}

impl RichText {
    /// Create a new RichText from text, optionally with pre-detected facets.
    pub fn new(text: impl Into<String>, facets: Option<Vec<Facet>>) -> Self {
        let text = text.into();
        let mut facets = facets.unwrap_or_default();
        // Filter invalid facets and sort by byte_start
        facets.retain(|f| f.index.byte_start < f.index.byte_end);
        facets.sort_by_key(|f| f.index.byte_start);
        RichText { text, facets }
    }

    /// The raw text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The facets.
    pub fn facets(&self) -> &[Facet] {
        &self.facets
    }

    /// UTF-8 byte length.
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Whether the text is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Grapheme cluster count (user-perceived characters).
    pub fn grapheme_length(&self) -> usize {
        self.text.graphemes(true).count()
    }

    /// Detect facets (mentions, links, tags) in the text.
    /// This does NOT resolve @mentions to DIDs — use `detect_facets_with_resolver`
    /// for that. Mentions will have `did` set to the handle text.
    pub fn detect_facets(&mut self) {
        self.facets = detect_facets(&self.text);
    }

    /// Insert text at a UTF-8 byte offset, adjusting facets.
    pub fn insert(&mut self, index: usize, insert_text: &str) {
        let added = insert_text.len();
        self.text.insert_str(index, insert_text);

        for facet in &mut self.facets {
            if index <= facet.index.byte_start {
                // Insert before facet: shift both
                facet.index.byte_start += added;
                facet.index.byte_end += added;
            } else if index < facet.index.byte_end {
                // Insert inside facet: expand end
                facet.index.byte_end += added;
            }
            // Insert after: no change
        }
    }

    /// Delete a byte range [start, end), adjusting facets.
    pub fn delete(&mut self, start: usize, end: usize) {
        let removed = end - start;

        // Replace the range in the string
        self.text.replace_range(start..end, "");

        for facet in &mut self.facets {
            let fs = facet.index.byte_start;
            let fe = facet.index.byte_end;

            if start <= fs && end >= fe {
                // A: Deletion spans entire facet → collapse
                facet.index.byte_start = start;
                facet.index.byte_end = start;
            } else if start >= fe {
                // B: Deletion entirely after facet → no change
            } else if start > fs && end >= fe {
                // C: Deletion overlaps end → truncate
                facet.index.byte_end = start;
            } else if start > fs && end < fe {
                // D: Deletion entirely inside facet → shrink
                facet.index.byte_end -= removed;
            } else if start <= fs && end > fs && end < fe {
                // E: Deletion overlaps start → shift start, shrink
                facet.index.byte_start = start;
                facet.index.byte_end -= removed;
            } else if end <= fs {
                // F: Deletion entirely before facet → shift both
                facet.index.byte_start -= removed;
                facet.index.byte_end -= removed;
            }
        }

        // Remove collapsed facets
        self.facets
            .retain(|f| f.index.byte_start < f.index.byte_end);
    }

    /// Iterate over segments of the rich text.
    pub fn segments(&self) -> Vec<RichTextSegment> {
        if self.facets.is_empty() {
            return vec![RichTextSegment {
                text: self.text.clone(),
                facet: None,
            }];
        }

        let mut segments = Vec::new();
        let mut cursor = 0;

        for facet in &self.facets {
            let start = facet.index.byte_start;
            let end = facet.index.byte_end.min(self.text.len());

            // Plain text before this facet
            if cursor < start {
                segments.push(RichTextSegment {
                    text: self.text[cursor..start].to_string(),
                    facet: None,
                });
            }

            // The faceted segment
            let seg_text = &self.text[start..end];
            if !seg_text.trim().is_empty() {
                segments.push(RichTextSegment {
                    text: seg_text.to_string(),
                    facet: Some(facet.clone()),
                });
            } else {
                segments.push(RichTextSegment {
                    text: seg_text.to_string(),
                    facet: None,
                });
            }

            cursor = end;
        }

        // Remaining text after last facet
        if cursor < self.text.len() {
            segments.push(RichTextSegment {
                text: self.text[cursor..].to_string(),
                facet: None,
            });
        }

        segments
    }
}

// --- Facet detection ---

static MENTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\s|\()(@)([a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,})")
        .expect("mention regex")
});

static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\s|\()(https?://[\S]+)").expect("url regex"));

static TAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\s)[#＃]([^\s\u{00AD}\u{2060}\u{200A}\u{200B}\u{200C}\u{200D}]*[^\d\s\p{Punctuation}\u{00AD}\u{2060}\u{200A}\u{200B}\u{200C}\u{200D}]+[^\s\u{00AD}\u{2060}\u{200A}\u{200B}\u{200C}\u{200D}]*)")
        .expect("tag regex")
});

/// Detect facets in text without DID resolution.
pub fn detect_facets(text: &str) -> Vec<Facet> {
    let mut facets = Vec::new();

    // Detect mentions: @handle.domain
    for cap in MENTION_RE.captures_iter(text) {
        let handle_match = cap.get(2).unwrap();
        let handle = handle_match.as_str();

        // byte_start from the '@', not from any leading whitespace
        let at_match = cap.get(1).unwrap();
        let byte_start = at_match.start();
        let byte_end = handle_match.end();

        facets.push(Facet {
            index: ByteSlice {
                byte_start,
                byte_end,
            },
            features: vec![FacetFeature::Mention {
                did: handle.to_string(),
            }],
        });
    }

    // Detect URLs
    for cap in URL_RE.captures_iter(text) {
        let url_match = cap.get(1).unwrap();
        let mut uri = url_match.as_str().to_string();
        let byte_start = url_match.start();
        let mut byte_end = url_match.end();

        // Strip trailing punctuation
        while uri.ends_with(['.', ',', ';', ':', '!', '?']) {
            uri.pop();
            byte_end -= 1;
        }

        // Strip trailing ')' if no '(' in URL
        if uri.ends_with(')') && !uri.contains('(') {
            uri.pop();
            byte_end -= 1;
        }

        facets.push(Facet {
            index: ByteSlice {
                byte_start,
                byte_end,
            },
            features: vec![FacetFeature::Link { uri }],
        });
    }

    // Detect hashtags: #tag
    for cap in TAG_RE.captures_iter(text) {
        let tag_match = cap.get(1).unwrap();
        let tag = tag_match.as_str();

        // Limit tags to 64 chars
        if tag.is_empty() || tag.len() > 64 {
            continue;
        }

        // Strip trailing punctuation from tag
        let tag_trimmed = tag.trim_end_matches(|c: char| c.is_ascii_punctuation());
        if tag_trimmed.is_empty() {
            continue;
        }

        // The full match includes the '#', find its byte position
        let full_match = cap.get(0).unwrap();
        // Find the '#' or '＃' in the full match
        let hash_pos = full_match
            .as_str()
            .find('#')
            .or_else(|| full_match.as_str().find('＃'))
            .unwrap_or(0);
        let byte_start = full_match.start() + hash_pos;
        let byte_end = byte_start + 1 + tag_trimmed.len(); // '#' + tag text

        // Clamp to not exceed text bounds
        let byte_end = byte_end.min(text.len());

        facets.push(Facet {
            index: ByteSlice {
                byte_start,
                byte_end,
            },
            features: vec![FacetFeature::Tag {
                tag: tag_trimmed.to_string(),
            }],
        });
    }

    facets.sort_by_key(|f| f.index.byte_start);
    facets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_text_no_facets() {
        let rt = RichText::new("Hello, world!", None);
        assert_eq!(rt.text(), "Hello, world!");
        assert!(rt.facets().is_empty());
        assert_eq!(rt.len(), 13);
        assert_eq!(rt.grapheme_length(), 13);
    }

    #[test]
    fn detect_mention() {
        let mut rt = RichText::new("Hello @alice.bsky.social!", None);
        rt.detect_facets();
        assert_eq!(rt.facets().len(), 1);
        let f = &rt.facets()[0];
        assert!(
            matches!(&f.features[0], FacetFeature::Mention { did } if did == "alice.bsky.social")
        );
        assert_eq!(
            &rt.text()[f.index.byte_start..f.index.byte_end],
            "@alice.bsky.social"
        );
    }

    #[test]
    fn detect_url() {
        let mut rt = RichText::new("Check https://example.com/path here", None);
        rt.detect_facets();
        assert_eq!(rt.facets().len(), 1);
        let f = &rt.facets()[0];
        assert!(
            matches!(&f.features[0], FacetFeature::Link { uri } if uri == "https://example.com/path")
        );
    }

    #[test]
    fn detect_url_strips_trailing_punctuation() {
        let mut rt = RichText::new("Visit https://example.com.", None);
        rt.detect_facets();
        assert_eq!(rt.facets().len(), 1);
        let f = &rt.facets()[0];
        assert!(
            matches!(&f.features[0], FacetFeature::Link { uri } if uri == "https://example.com")
        );
    }

    #[test]
    fn detect_url_strips_trailing_paren_without_open() {
        let mut rt = RichText::new("(see https://example.com/page)", None);
        rt.detect_facets();
        assert_eq!(rt.facets().len(), 1);
        let f = &rt.facets()[0];
        // URL doesn't contain '(' so trailing ')' is stripped
        assert!(
            matches!(&f.features[0], FacetFeature::Link { uri } if uri == "https://example.com/page")
        );
    }

    #[test]
    fn detect_hashtag() {
        let mut rt = RichText::new("Hello #atproto world", None);
        rt.detect_facets();
        assert_eq!(rt.facets().len(), 1);
        let f = &rt.facets()[0];
        assert!(matches!(&f.features[0], FacetFeature::Tag { tag } if tag == "atproto"));
    }

    #[test]
    fn detect_multiple_facets() {
        let mut rt = RichText::new("@alice.test posted https://example.com #cool", None);
        rt.detect_facets();
        assert_eq!(rt.facets().len(), 3);
        assert!(
            rt.facets()[0]
                .features
                .iter()
                .any(|f| matches!(f, FacetFeature::Mention { .. }))
        );
        assert!(
            rt.facets()[1]
                .features
                .iter()
                .any(|f| matches!(f, FacetFeature::Link { .. }))
        );
        assert!(
            rt.facets()[2]
                .features
                .iter()
                .any(|f| matches!(f, FacetFeature::Tag { .. }))
        );
    }

    #[test]
    fn segments_no_facets() {
        let rt = RichText::new("Hello world", None);
        let segs = rt.segments();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].text, "Hello world");
        assert!(segs[0].facet.is_none());
    }

    #[test]
    fn segments_with_facets() {
        let mut rt = RichText::new("Hello @alice.test world", None);
        rt.detect_facets();
        let segs = rt.segments();
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0].text, "Hello ");
        assert!(segs[0].facet.is_none());
        assert_eq!(segs[1].text, "@alice.test");
        assert!(segs[1].is_mention());
        assert_eq!(segs[2].text, " world");
        assert!(segs[2].facet.is_none());
    }

    #[test]
    fn insert_before_facet() {
        let facets = vec![Facet {
            index: ByteSlice {
                byte_start: 6,
                byte_end: 11,
            },
            features: vec![FacetFeature::Tag {
                tag: "test".to_string(),
            }],
        }];
        let mut rt = RichText::new("Hello #test", Some(facets));
        rt.insert(0, "Hey ");
        assert_eq!(rt.text(), "Hey Hello #test");
        assert_eq!(rt.facets()[0].index.byte_start, 10);
        assert_eq!(rt.facets()[0].index.byte_end, 15);
    }

    #[test]
    fn insert_inside_facet() {
        let facets = vec![Facet {
            index: ByteSlice {
                byte_start: 0,
                byte_end: 5,
            },
            features: vec![FacetFeature::Link {
                uri: "https://example.com".to_string(),
            }],
        }];
        let mut rt = RichText::new("Hello world", Some(facets));
        rt.insert(3, "XX");
        assert_eq!(rt.text(), "HelXXlo world");
        assert_eq!(rt.facets()[0].index.byte_start, 0);
        assert_eq!(rt.facets()[0].index.byte_end, 7);
    }

    #[test]
    fn delete_before_facet() {
        let facets = vec![Facet {
            index: ByteSlice {
                byte_start: 6,
                byte_end: 11,
            },
            features: vec![FacetFeature::Tag {
                tag: "test".to_string(),
            }],
        }];
        let mut rt = RichText::new("Hello #test", Some(facets));
        rt.delete(0, 6);
        assert_eq!(rt.text(), "#test");
        assert_eq!(rt.facets()[0].index.byte_start, 0);
        assert_eq!(rt.facets()[0].index.byte_end, 5);
    }

    #[test]
    fn delete_spanning_facet_removes_it() {
        let facets = vec![Facet {
            index: ByteSlice {
                byte_start: 6,
                byte_end: 11,
            },
            features: vec![FacetFeature::Tag {
                tag: "test".to_string(),
            }],
        }];
        let mut rt = RichText::new("Hello #test world", Some(facets));
        rt.delete(5, 12);
        assert_eq!(rt.text(), "Helloworld");
        assert!(rt.facets().is_empty());
    }

    #[test]
    fn grapheme_length_emoji() {
        let rt = RichText::new("Hi 👋🏽", None);
        // "Hi " = 3 graphemes, flag + skin tone = 1 grapheme
        assert_eq!(rt.grapheme_length(), 4);
        // But byte length is much longer (emoji is multi-byte)
        assert!(rt.len() > 4);
    }

    #[test]
    fn utf8_byte_offsets_work_natively() {
        // In Rust, string indexing is already UTF-8 bytes
        let text = "Héllo @alice.test";
        let mut rt = RichText::new(text, None);
        rt.detect_facets();
        assert_eq!(rt.facets().len(), 1);
        let f = &rt.facets()[0];
        assert_eq!(
            &rt.text()[f.index.byte_start..f.index.byte_end],
            "@alice.test"
        );
    }

    #[test]
    fn empty_text() {
        let rt = RichText::new("", None);
        assert!(rt.is_empty());
        assert_eq!(rt.len(), 0);
        assert_eq!(rt.grapheme_length(), 0);
        let segs = rt.segments();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].text, "");
    }

    #[test]
    fn facet_feature_serde_roundtrip() {
        let facet = Facet {
            index: ByteSlice {
                byte_start: 0,
                byte_end: 5,
            },
            features: vec![FacetFeature::Mention {
                did: "did:plc:abc123".to_string(),
            }],
        };
        let json = serde_json::to_string(&facet).unwrap();
        assert!(json.contains("app.bsky.richtext.facet#mention"));
        let parsed: Facet = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.index.byte_start, 0);
        assert!(
            matches!(&parsed.features[0], FacetFeature::Mention { did } if did == "did:plc:abc123")
        );
    }
}
