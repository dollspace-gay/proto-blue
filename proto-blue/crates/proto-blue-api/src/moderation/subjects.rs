//! Top-level moderation entry points: `decide_account`, `decide_profile`,
//! `decide_post`, plus the embed walker used when a post quotes another.
//!
//! These mirror TS `@atproto/api` `moderation/subjects/*` — they accept
//! shallow `SubjectAccount` / `SubjectProfile` / `SubjectPost` structs
//! assembled from a generated `ProfileView` / `PostView`, apply
//! label-preference resolution, block / mute / mute-word / hidden
//! signal aggregation, and for posts walk embedded records so that
//! quoted-post moderation downgrades propagate to the outer decision.
//!
//! The shapes are explicit (rather than pattern-matching the generated
//! types directly) because moderation logic shouldn't churn every time
//! a lexicon schema adds a field. Callers typically use the
//! `moderate_post(view, opts)` convenience at the top of this file to
//! translate a generated `PostView` into a `SubjectPost` automatically.

use super::decision::ModerationDecision;
use super::mutewords::{MutedWordMatch, check_muted_words};
use super::types::*;

use serde_json::Value as JsonValue;

/// Account-level moderation inputs (the "is this user OK to interact
/// with at all" level).
#[derive(Debug, Clone)]
pub struct SubjectAccount<'a> {
    pub did: &'a str,
    /// Raw labels attached to the account (server + user-subscribed labelers).
    pub labels: &'a [LabelData],
    /// `true` when the viewer blocks this account.
    pub viewer_blocking: bool,
    /// `true` when this account blocks the viewer.
    pub viewer_blocked_by: bool,
    /// `true` when the viewer muted the account.
    pub viewer_muted: bool,
    /// If the viewer is muted via a moderation list, the list URI and name.
    pub viewer_muted_by_list: Option<(String, String)>,
    /// If the viewer is blocked via a moderation list, the list URI and name.
    pub viewer_blocking_by_list: Option<(String, String)>,
}

/// Profile-level moderation inputs.
#[derive(Debug, Clone)]
pub struct SubjectProfile<'a> {
    pub did: &'a str,
    /// Labels attached specifically to the profile record.
    pub labels: &'a [LabelData],
}

/// Post-level moderation inputs, including optional quote-embed payload.
#[derive(Debug, Clone)]
pub struct SubjectPost<'a> {
    /// The post author's account-level subject (labels, blocks, mutes, …).
    pub author: SubjectAccount<'a>,
    /// Post-content labels (attached via `app.bsky.feed.post` labels).
    pub labels: &'a [LabelData],
    /// The literal post text — used for mute-word matching.
    pub text: &'a str,
    /// Post languages (`record.langs`) — narrows mute-word matching.
    pub languages: &'a [String],
    /// `true` when the viewer has explicitly hidden this post.
    pub hidden: bool,
    /// Optional embedded quote. When present, moderation for the
    /// quoted record is walked recursively and downgraded into this
    /// post's decision.
    pub embed: Option<QuoteEmbed<'a>>,
}

/// A quoted-post embed payload (produced either from
/// `app.bsky.embed.record#view` or the record half of
/// `app.bsky.embed.recordWithMedia#view`).
#[derive(Debug, Clone)]
pub struct QuoteEmbed<'a> {
    pub author: SubjectAccount<'a>,
    pub labels: &'a [LabelData],
    pub text: &'a str,
    pub languages: &'a [String],
}

/// Decide moderation for an account subject.
///
/// Aggregates blocks / mutes / labels. The result is a single
/// [`ModerationDecision`] suitable for feeding into [`ModerationUi`]
/// via the existing behavior priority machinery.
pub fn decide_account(subject: &SubjectAccount, opts: &ModerationOpts) -> ModerationDecision {
    let is_me = opts.user_did.as_deref() == Some(subject.did);
    let mut d = ModerationDecision::new(subject.did, is_me);

    // Block / mute signals never apply to the viewer themselves —
    // matches TS `moderation/decision.ts`.
    if !is_me {
        if subject.viewer_blocking {
            d.add_blocking(ModerationCauseSource::User);
        }
        if subject.viewer_blocked_by {
            d.add_blocked_by(ModerationCauseSource::User);
        }
        if let Some((uri, name)) = &subject.viewer_blocking_by_list {
            d.add_block_other(ModerationCauseSource::List {
                uri: uri.clone(),
                name: name.clone(),
            });
        }
        if subject.viewer_muted {
            d.add_muted(ModerationCauseSource::User);
        }
        if let Some((uri, name)) = &subject.viewer_muted_by_list {
            d.add_muted(ModerationCauseSource::List {
                uri: uri.clone(),
                name: name.clone(),
            });
        }
    }

    for label in subject.labels.iter().filter(|l| l.neg != Some(true)) {
        d.add_label(label.clone(), LabelTarget::Account, opts);
    }
    d
}

/// Decide moderation for a profile subject.
///
/// Profile-level labels are separate from account-level: a user can
/// label their own profile (e.g. `porn`) without that label propagating
/// to account interactions.
pub fn decide_profile(subject: &SubjectProfile, opts: &ModerationOpts) -> ModerationDecision {
    let is_me = opts.user_did.as_deref() == Some(subject.did);
    let mut d = ModerationDecision::new(subject.did, is_me);
    for label in subject.labels.iter().filter(|l| l.neg != Some(true)) {
        d.add_label(label.clone(), LabelTarget::Profile, opts);
    }
    d
}

/// Decide moderation for a post subject, walking a quote embed if
/// present.
///
/// The algorithm mirrors TS `moderation/subjects/post.ts`:
///
/// 1. Decide the post's own author (account-level signals).
/// 2. Decide the post's content labels.
/// 3. Mute-word match against `text` narrowed by `languages`.
/// 4. If `hidden` is set, add a Hidden cause.
/// 5. If there's a quote embed, decide that recursively, **downgrade**
///    every cause from it, and merge into the outer decision.
///
/// The downgrade step is what makes a quote of a blocked user render
/// with a warning instead of a hard filter — the outer post hasn't
/// done anything wrong.
pub fn decide_post(subject: &SubjectPost, opts: &ModerationOpts) -> ModerationDecision {
    let mut d = decide_account(&subject.author, opts);

    for label in subject.labels.iter().filter(|l| l.neg != Some(true)) {
        d.add_label(label.clone(), LabelTarget::Content, opts);
    }

    // Mute-word match against the post text.
    let matches: Vec<MutedWordMatch> = check_muted_words(
        &opts.prefs.muted_words,
        subject.text,
        /*tags=*/ &[],
        subject.languages,
        /*is_following_author=*/ false,
    );
    if !matches.is_empty() {
        d.add_mute_word(ModerationCauseSource::User);
    }

    if subject.hidden {
        d.add_hidden(ModerationCauseSource::User);
    }

    if let Some(embed) = &subject.embed {
        let mut inner = decide_account(&embed.author, opts);
        for label in embed.labels.iter().filter(|l| l.neg != Some(true)) {
            inner.add_label(label.clone(), LabelTarget::Content, opts);
        }
        let embed_matches: Vec<MutedWordMatch> = check_muted_words(
            &opts.prefs.muted_words,
            embed.text,
            /*tags=*/ &[],
            embed.languages,
            /*is_following_author=*/ false,
        );
        if !embed_matches.is_empty() {
            inner.add_mute_word(ModerationCauseSource::User);
        }
        // Downgrade every cause from the quoted content — the outer
        // post is what the user is reading; we want a softer signal.
        inner.downgrade();
        // Merge the downgraded inner causes into the outer decision.
        d.causes.extend(inner.causes);
    }

    d
}

/// Extract a quote embed from a generated `PostView.embed` JSON value.
///
/// Returns `None` when the embed is absent, of a non-quote kind
/// (images, external, video), or malformed. Handles both
/// `app.bsky.embed.record#view` (plain quote) and
/// `app.bsky.embed.recordWithMedia#view` (quote with media — we
/// extract only the record half; media moderation happens at the
/// account/label level on the outer post).
///
/// This probes raw JSON because `PostView.embed` is a serde_json
/// `Value` — the embed is a union of several unrelated view types.
pub fn extract_quote_embed(embed: &JsonValue) -> Option<EmbedView<'_>> {
    let ty = embed.get("$type")?.as_str()?;
    let record = match ty {
        "app.bsky.embed.record#view" => embed.get("record")?,
        "app.bsky.embed.recordWithMedia#view" => {
            embed.get("record")?.get("record")?
        }
        _ => return None,
    };
    // A quoted record can itself be a `viewRecord`, `viewNotFound`,
    // `viewBlocked`, etc. We only extract quote-content when it's a
    // `viewRecord` — the other shapes produce specific moderation
    // signals that the caller can surface directly (the data isn't
    // there to decide).
    let record_ty = record.get("$type")?.as_str()?;
    if record_ty != "app.bsky.embed.record#viewRecord" {
        return None;
    }
    Some(EmbedView { record })
}

/// Borrowed view over a quoted-post JSON record.
pub struct EmbedView<'a> {
    pub record: &'a JsonValue,
}

impl<'a> EmbedView<'a> {
    pub fn author_did(&self) -> Option<&'a str> {
        self.record.get("author")?.get("did")?.as_str()
    }

    pub fn text(&self) -> Option<&'a str> {
        self.record.get("value")?.get("text")?.as_str()
    }

    pub fn languages(&self) -> Vec<String> {
        self.record
            .get("value")
            .and_then(|v| v.get("langs"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn labels(&self) -> Vec<LabelData> {
        self.record
            .get("labels")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| serde_json::from_value::<LabelData>(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base_opts() -> ModerationOpts {
        ModerationOpts {
            user_did: Some("did:plc:viewer".into()),
            prefs: ModerationPrefs {
                adult_content_enabled: false,
                labels: HashMap::new(),
                labelers: Vec::new(),
                muted_words: Vec::new(),
                hidden_posts: Vec::new(),
            },
            label_defs: HashMap::new(),
        }
    }

    fn subject_account<'a>(did: &'a str) -> SubjectAccount<'a> {
        SubjectAccount {
            did,
            labels: &[],
            viewer_blocking: false,
            viewer_blocked_by: false,
            viewer_muted: false,
            viewer_muted_by_list: None,
            viewer_blocking_by_list: None,
        }
    }

    #[test]
    fn decide_account_clean_yields_no_causes() {
        let a = subject_account("did:plc:alice");
        let d = decide_account(&a, &base_opts());
        assert!(d.causes.is_empty());
    }

    #[test]
    fn decide_account_blocking_adds_cause() {
        let a = SubjectAccount {
            viewer_blocking: true,
            ..subject_account("did:plc:alice")
        };
        let d = decide_account(&a, &base_opts());
        assert_eq!(d.causes.len(), 1);
        assert!(matches!(d.causes[0], ModerationCause::Blocking { .. }));
    }

    #[test]
    fn decide_account_self_ignores_blocks_and_mutes() {
        // If subject.did == opts.user_did, blocking/muting/etc don't apply.
        let a = SubjectAccount {
            viewer_blocking: true,
            viewer_muted: true,
            ..subject_account("did:plc:viewer")
        };
        let d = decide_account(&a, &base_opts());
        assert!(d.causes.is_empty(), "self-block should not produce causes");
        assert!(d.is_me);
    }

    #[test]
    fn decide_account_negated_label_is_skipped() {
        let labels = vec![LabelData {
            src: "did:plc:labeler".into(),
            uri: "at://did:plc:alice".into(),
            val: "spam".into(),
            neg: Some(true),
        }];
        let a = SubjectAccount {
            labels: &labels,
            ..subject_account("did:plc:alice")
        };
        let d = decide_account(&a, &base_opts());
        assert!(d.causes.is_empty(), "negated label should not apply");
    }

    #[test]
    fn decide_post_hidden_adds_cause() {
        let a = subject_account("did:plc:alice");
        let post = SubjectPost {
            author: a,
            labels: &[],
            text: "hi",
            languages: &[],
            hidden: true,
            embed: None,
        };
        let d = decide_post(&post, &base_opts());
        assert!(d.causes.iter().any(|c| matches!(c, ModerationCause::Hidden { .. })));
    }

    #[test]
    fn decide_post_embed_causes_are_downgraded() {
        // The outer post has no causes; the quoted author is blocked.
        // After merge the inner Blocking cause must appear on the
        // outer decision AND be marked downgraded.
        let outer = subject_account("did:plc:alice");
        let inner = SubjectAccount {
            viewer_blocking: true,
            ..subject_account("did:plc:bob")
        };
        let embed = QuoteEmbed {
            author: inner,
            labels: &[],
            text: "quoted",
            languages: &[],
        };
        let post = SubjectPost {
            author: outer,
            labels: &[],
            text: "i'm quoting bob",
            languages: &[],
            hidden: false,
            embed: Some(embed),
        };
        let d = decide_post(&post, &base_opts());
        let blocking = d
            .causes
            .iter()
            .find(|c| matches!(c, ModerationCause::Blocking { .. }))
            .expect("inner blocking cause should propagate");
        assert!(
            blocking.is_downgraded(),
            "embed-derived causes must be downgraded",
        );
    }

    #[test]
    fn decide_post_mute_word_match_adds_cause() {
        let mut opts = base_opts();
        opts.prefs.muted_words.push(MutedWord {
            value: "forbidden".into(),
            targets: vec!["content".into()],
            actor_target: None,
            expires_at: None,
        });
        let a = subject_account("did:plc:alice");
        let post = SubjectPost {
            author: a,
            labels: &[],
            text: "contains the forbidden word",
            languages: &[],
            hidden: false,
            embed: None,
        };
        let d = decide_post(&post, &opts);
        assert!(d.causes.iter().any(|c| matches!(c, ModerationCause::MuteWord { .. })));
    }

    #[test]
    fn extract_quote_embed_from_record_view() {
        let embed = serde_json::json!({
            "$type": "app.bsky.embed.record#view",
            "record": {
                "$type": "app.bsky.embed.record#viewRecord",
                "uri": "at://did:plc:bob/app.bsky.feed.post/abc",
                "cid": "bafy",
                "author": {"did": "did:plc:bob", "handle": "bob.bsky.social"},
                "value": {"text": "quoted content", "langs": ["en", "es"]},
                "labels": []
            }
        });
        let view = extract_quote_embed(&embed).expect("should extract");
        assert_eq!(view.author_did(), Some("did:plc:bob"));
        assert_eq!(view.text(), Some("quoted content"));
        assert_eq!(view.languages(), vec!["en", "es"]);
    }

    #[test]
    fn extract_quote_embed_from_record_with_media() {
        let embed = serde_json::json!({
            "$type": "app.bsky.embed.recordWithMedia#view",
            "record": {
                "$type": "app.bsky.embed.record#view",
                "record": {
                    "$type": "app.bsky.embed.record#viewRecord",
                    "uri": "at://did:plc:bob/app.bsky.feed.post/abc",
                    "cid": "bafy",
                    "author": {"did": "did:plc:bob", "handle": "bob"},
                    "value": {"text": "with media"},
                    "labels": []
                }
            },
            "media": {"$type": "app.bsky.embed.images#view"}
        });
        let view = extract_quote_embed(&embed).expect("should extract record side");
        assert_eq!(view.text(), Some("with media"));
    }

    #[test]
    fn extract_quote_embed_returns_none_for_plain_images() {
        let embed = serde_json::json!({
            "$type": "app.bsky.embed.images#view",
            "images": []
        });
        assert!(extract_quote_embed(&embed).is_none());
    }

    #[test]
    fn extract_quote_embed_returns_none_for_view_blocked() {
        let embed = serde_json::json!({
            "$type": "app.bsky.embed.record#view",
            "record": {
                "$type": "app.bsky.embed.record#viewBlocked",
                "uri": "at://did:plc:x/app.bsky.feed.post/y",
                "blocked": true
            }
        });
        assert!(extract_quote_embed(&embed).is_none());
    }
}
