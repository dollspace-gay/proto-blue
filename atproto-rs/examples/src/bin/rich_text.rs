//! Example: Rich text facet detection.
//!
//! Demonstrates creating rich text with automatic facet detection
//! for mentions, links, and hashtags.
//!
//! Run with: cargo run -p atproto-examples --bin rich_text

use atproto_api::rich_text::{FacetFeature, RichText};

fn main() {
    println!("=== AT Protocol Rich Text ===\n");

    // --- Basic facet detection ---
    println!("--- Facet Detection ---");
    let text = "Hello @alice.bsky.social! Check out https://bsky.app #atproto";
    let mut rt = RichText::new(text.to_string(), None);
    rt.detect_facets();

    println!("  Text: \"{}\"", rt.text());
    println!("  Facets detected: {}", rt.facets().len());
    for facet in rt.facets() {
        let slice = &rt.text()[facet.index.byte_start..facet.index.byte_end];
        let kind = match &facet.features[0] {
            FacetFeature::Mention { did } => format!("Mention -> {}", did),
            FacetFeature::Link { uri } => format!("Link -> {}", uri),
            FacetFeature::Tag { tag } => format!("Tag -> #{}", tag),
        };
        println!(
            "  [{}-{}] \"{}\" => {}",
            facet.index.byte_start, facet.index.byte_end, slice, kind
        );
    }

    // --- UTF-8 byte offsets ---
    println!("\n--- UTF-8 Byte Offsets (native advantage in Rust!) ---");
    let emoji_text = "Hello! Check out https://bsky.app for more info";
    let mut rt2 = RichText::new(emoji_text.to_string(), None);
    rt2.detect_facets();
    println!("  Text: \"{}\"", rt2.text());
    println!("  Text byte length: {}", rt2.text().len());
    println!(
        "  Grapheme length: {}",
        atproto_common::grapheme_len(rt2.text())
    );
    for facet in rt2.facets() {
        println!(
            "  Facet at bytes [{}-{}]: \"{}\"",
            facet.index.byte_start,
            facet.index.byte_end,
            &rt2.text()[facet.index.byte_start..facet.index.byte_end]
        );
    }

    // --- Insert and delete with facet adjustment ---
    println!("\n--- Text Manipulation ---");
    let mut rt3 = RichText::new("Hello @bob.bsky.social world".to_string(), None);
    rt3.detect_facets();
    println!(
        "  Original: \"{}\" ({} facets)",
        rt3.text(),
        rt3.facets().len()
    );

    // Insert text before the mention
    rt3.insert(0, "Hey! ");
    println!(
        "  After insert: \"{}\" ({} facets)",
        rt3.text(),
        rt3.facets().len()
    );
    if let Some(f) = rt3.facets().first() {
        println!(
            "    Mention shifted to [{}-{}]",
            f.index.byte_start, f.index.byte_end
        );
    }

    // --- Segments ---
    println!("\n--- Segments ---");
    let text = "Post by @alice.bsky.social about #rust and https://example.com";
    let mut rt5 = RichText::new(text.to_string(), None);
    rt5.detect_facets();
    let segments = rt5.segments();
    println!("  Text: \"{}\"", rt5.text());
    println!("  Segments:");
    for seg in &segments {
        if let Some(facet) = &seg.facet {
            let kind = match &facet.features[0] {
                FacetFeature::Mention { .. } => "mention",
                FacetFeature::Link { .. } => "link",
                FacetFeature::Tag { .. } => "tag",
            };
            println!("    [{}] \"{}\"", kind, seg.text);
        } else {
            println!("    [text] \"{}\"", seg.text);
        }
    }

    // --- Multiple mentions ---
    println!("\n--- Multiple Mentions ---");
    let multi = "cc @alice.bsky.social @bob.bsky.social @carol.bsky.social";
    let mut rt6 = RichText::new(multi.to_string(), None);
    rt6.detect_facets();
    println!("  Text: \"{}\"", rt6.text());
    println!("  Mentions found: {}", rt6.facets().len());

    println!("\nDone!");
}
