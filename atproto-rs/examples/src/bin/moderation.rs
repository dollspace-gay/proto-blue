//! Example: Content moderation decisions.
//!
//! Demonstrates the moderation engine: label-based decisions,
//! mute words, blocking, and UI context filtering.
//!
//! Run with: cargo run -p proto-blue-examples --bin moderation

use proto_blue_api::moderation::{
    decision::ModerationDecision, labels::known_labels, mutewords::check_muted_words, types::*,
};

fn main() {
    println!("=== AT Protocol Content Moderation ===\n");

    // --- Known system labels ---
    println!("--- Known System Labels ---");
    let labels = known_labels();
    for def in &labels {
        println!(
            "  {}: blurs={:?}, severity={:?}, default={:?}",
            def.identifier, def.blurs, def.severity, def.default_setting
        );
    }

    // --- Label-based moderation ---
    println!("\n--- Label-Based Moderation ---");
    let opts = ModerationOpts {
        user_did: Some("did:plc:viewer123".into()),
        prefs: ModerationPrefs {
            adult_content_enabled: false,
            labels: std::collections::HashMap::from([
                ("porn".into(), LabelPreference::Hide),
                ("graphic-media".into(), LabelPreference::Warn),
            ]),
            labelers: Vec::new(),
            muted_words: Vec::new(),
            hidden_posts: Vec::new(),
        },
        label_defs: std::collections::HashMap::new(),
    };

    // Simulate a post with a "porn" label
    let mut decision = ModerationDecision::new("did:plc:author", false);
    decision.add_label(
        LabelData {
            src: "did:plc:labeler".into(),
            uri: "at://did:plc:author/app.bsky.feed.post/abc".into(),
            val: "porn".into(),
            neg: None,
        },
        LabelTarget::Content,
        &opts,
    );

    // Check different UI contexts
    println!("  Post with 'porn' label (adult content disabled):");
    for ctx in [
        UiContext::ContentList,
        UiContext::ContentView,
        UiContext::ContentMedia,
        UiContext::ProfileView,
    ] {
        let ui = decision.ui(ctx);
        println!(
            "    {:?}: filter={}, blur={}, alert={}, inform={}",
            ctx,
            ui.filter(),
            ui.blur(),
            ui.alert(),
            ui.inform()
        );
    }

    // --- Blocking ---
    println!("\n--- Block Decisions ---");
    let mut block_decision = ModerationDecision::new("did:plc:blocked-user", false);
    block_decision.add_blocking(ModerationCauseSource::User);

    println!("  Blocked user:");
    let ui = block_decision.ui(UiContext::ContentList);
    println!(
        "    ContentList: filter={}, blur={}",
        ui.filter(),
        ui.blur()
    );
    let ui = block_decision.ui(UiContext::ProfileView);
    println!(
        "    ProfileView: filter={}, blur={}",
        ui.filter(),
        ui.blur()
    );

    // --- Muted user ---
    println!("\n--- Muted User ---");
    let mut mute_decision = ModerationDecision::new("did:plc:muted-user", false);
    mute_decision.add_muted(ModerationCauseSource::User);

    println!("  Muted user:");
    let ui = mute_decision.ui(UiContext::ContentList);
    println!("    ContentList: filter={}", ui.filter());

    // --- Mute words ---
    println!("\n--- Mute Word Matching ---");
    let muted_words = vec![
        MutedWord {
            value: "crypto".into(),
            targets: vec!["content".into()],
            actor_target: Some("all".into()),
            expires_at: None,
        },
        MutedWord {
            value: "spoiler".into(),
            targets: vec!["content".into(), "tag".into()],
            actor_target: Some("all".into()),
            expires_at: None,
        },
        MutedWord {
            value: "NFT".into(),
            targets: vec!["content".into()],
            actor_target: Some("all".into()),
            expires_at: None,
        },
    ];

    let test_posts = [
        ("Just had a great day!", vec![]),
        ("New crypto token launching!", vec![]),
        ("Check out this NFT collection", vec![]),
        (
            "No filter words here, just #spoiler",
            vec!["spoiler".to_string()],
        ),
        ("Regular post", vec!["crypto".to_string()]),
    ];

    for (text, tags) in &test_posts {
        let matches = check_muted_words(
            &muted_words,
            text,
            tags,
            &[],   // no languages
            false, // not following
        );
        println!(
            "  \"{}\" [tags: {:?}] -> {}",
            text,
            tags,
            if !matches.is_empty() {
                "MUTED"
            } else {
                "visible"
            }
        );
    }

    // --- Merging decisions ---
    println!("\n--- Merged Decisions ---");
    let mut d1 = ModerationDecision::new("did:plc:author", false);
    d1.add_muted(ModerationCauseSource::User);
    let mut d2 = ModerationDecision::new("did:plc:author", false);
    d2.add_label(
        LabelData {
            src: "did:plc:labeler".into(),
            uri: "at://did:plc:author/app.bsky.feed.post/xyz".into(),
            val: "graphic-media".into(),
            neg: None,
        },
        LabelTarget::Content,
        &opts,
    );
    let merged = ModerationDecision::merge(vec![d1, d2]);
    let ui = merged.ui(UiContext::ContentList);
    println!("  Muted + graphic-media label:");
    println!(
        "    ContentList: filter={}, blur={}, causes={}",
        ui.filter(),
        ui.blur(),
        merged.causes.len()
    );

    println!("\nDone!");
}
