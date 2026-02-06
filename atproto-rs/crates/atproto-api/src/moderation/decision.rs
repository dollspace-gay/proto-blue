//! Moderation decision engine.
//!
//! Aggregates moderation causes (labels, blocks, mutes, hidden posts)
//! and produces UI decisions for each context.

use super::labels;
use super::types::*;

/// A moderation decision for a subject (profile, post, etc.).
#[derive(Debug, Clone)]
pub struct ModerationDecision {
    pub did: String,
    pub is_me: bool,
    pub causes: Vec<ModerationCause>,
}

impl ModerationDecision {
    /// Create a new empty decision.
    pub fn new(did: &str, is_me: bool) -> Self {
        ModerationDecision {
            did: did.to_string(),
            is_me,
            causes: Vec::new(),
        }
    }

    /// Merge multiple decisions into one (flattening all causes).
    pub fn merge(decisions: Vec<ModerationDecision>) -> ModerationDecision {
        let did = decisions.first().map(|d| d.did.clone()).unwrap_or_default();
        let is_me = decisions.first().map(|d| d.is_me).unwrap_or(false);
        let causes = decisions.into_iter().flat_map(|d| d.causes).collect();
        ModerationDecision { did, is_me, causes }
    }

    /// Mark all causes as downgraded (used for quoted/embedded content).
    pub fn downgrade(&mut self) {
        for cause in &mut self.causes {
            cause.set_downgraded();
        }
    }

    /// Add a blocking cause.
    pub fn add_blocking(&mut self, source: ModerationCauseSource) {
        self.causes.push(ModerationCause::Blocking {
            source,
            priority: 3,
            downgraded: false,
        });
    }

    /// Add a blocked-by cause.
    pub fn add_blocked_by(&mut self, source: ModerationCauseSource) {
        self.causes.push(ModerationCause::BlockedBy {
            source,
            priority: 4,
            downgraded: false,
        });
    }

    /// Add a block-other cause.
    pub fn add_block_other(&mut self, source: ModerationCauseSource) {
        self.causes.push(ModerationCause::BlockOther {
            source,
            priority: 4,
            downgraded: false,
        });
    }

    /// Add a muted cause.
    pub fn add_muted(&mut self, source: ModerationCauseSource) {
        self.causes.push(ModerationCause::Muted {
            source,
            priority: 6,
            downgraded: false,
        });
    }

    /// Add a mute word cause.
    pub fn add_mute_word(&mut self, source: ModerationCauseSource) {
        self.causes.push(ModerationCause::MuteWord {
            source,
            priority: 6,
            downgraded: false,
        });
    }

    /// Add a hidden cause.
    pub fn add_hidden(&mut self, source: ModerationCauseSource) {
        self.causes.push(ModerationCause::Hidden {
            source,
            priority: 6,
            downgraded: false,
        });
    }

    /// Add a label cause with preference resolution.
    pub fn add_label(&mut self, label: LabelData, target: LabelTarget, opts: &ModerationOpts) {
        // Look up label definition
        let label_def = match labels::find_label_def(&label.val, &opts.label_defs) {
            Some(def) => def,
            None => return, // Unknown label, ignore
        };

        // Resolve preference
        let setting = resolve_label_preference(&label, &label_def, opts);

        // If preference is Ignore and label is configurable, skip
        if setting == LabelPreference::Ignore && label_def.configurable {
            return;
        }

        // Calculate priority
        let priority = calculate_label_priority(&label_def, setting, opts);

        // Check no-override
        let no_override = label_def.flags.contains(&LabelFlag::NoOverride)
            || (label_def.flags.contains(&LabelFlag::Adult) && !opts.prefs.adult_content_enabled);

        let source = ModerationCauseSource::Labeler {
            did: label.src.clone(),
        };

        self.causes.push(ModerationCause::Label {
            source,
            label,
            label_def,
            target,
            setting,
            no_override,
            priority,
            downgraded: false,
        });
    }

    /// Generate the moderation UI for a given context.
    pub fn ui(&self, context: UiContext) -> ModerationUi {
        let mut ui = ModerationUi::default();

        // Sort causes by priority (lower = higher priority)
        let mut sorted_causes = self.causes.clone();
        sorted_causes.sort_by_key(|c| c.priority());

        for cause in &sorted_causes {
            match cause {
                ModerationCause::Blocking { downgraded, .. }
                | ModerationCause::BlockedBy { downgraded, .. }
                | ModerationCause::BlockOther { downgraded, .. } => {
                    if self.is_me {
                        continue;
                    }
                    let behavior = labels::block_behavior();
                    apply_behavior(&mut ui, cause, &behavior, context, *downgraded);
                    // Blocks filter in list contexts
                    if matches!(context, UiContext::ProfileList | UiContext::ContentList) {
                        ui.filters.push(cause.clone());
                    }
                }
                ModerationCause::Muted { downgraded, .. } => {
                    if self.is_me {
                        continue;
                    }
                    let behavior = labels::mute_behavior();
                    apply_behavior(&mut ui, cause, &behavior, context, *downgraded);
                    if matches!(context, UiContext::ProfileList | UiContext::ContentList) {
                        ui.filters.push(cause.clone());
                    }
                }
                ModerationCause::MuteWord { downgraded, .. } => {
                    if self.is_me {
                        continue;
                    }
                    let behavior = labels::mute_word_behavior();
                    apply_behavior(&mut ui, cause, &behavior, context, *downgraded);
                    if context == UiContext::ContentList {
                        ui.filters.push(cause.clone());
                    }
                }
                ModerationCause::Hidden { downgraded, .. } => {
                    let behavior = labels::hide_behavior();
                    apply_behavior(&mut ui, cause, &behavior, context, *downgraded);
                    if matches!(context, UiContext::ProfileList | UiContext::ContentList) {
                        ui.filters.push(cause.clone());
                    }
                }
                ModerationCause::Label {
                    label_def,
                    target,
                    setting,
                    no_override,
                    downgraded,
                    ..
                } => {
                    // Label-specific filtering for hide preference
                    if *setting == LabelPreference::Hide && !self.is_me {
                        match (context, target) {
                            (UiContext::ProfileList, LabelTarget::Account) => {
                                ui.filters.push(cause.clone());
                            }
                            (
                                UiContext::ContentList,
                                LabelTarget::Account | LabelTarget::Content,
                            ) => {
                                ui.filters.push(cause.clone());
                            }
                            _ => {}
                        }
                    }

                    // Get behavior for the target
                    let behavior = match target {
                        LabelTarget::Account => &label_def.behaviors.account,
                        LabelTarget::Profile => &label_def.behaviors.profile,
                        LabelTarget::Content => &label_def.behaviors.content,
                    };

                    if !downgraded {
                        if let Some(action) = behavior.get(context) {
                            match action {
                                BehaviorValue::Blur => {
                                    ui.blurs.push(cause.clone());
                                    if *no_override {
                                        ui.no_override = true;
                                    }
                                }
                                BehaviorValue::Alert => ui.alerts.push(cause.clone()),
                                BehaviorValue::Inform => ui.informs.push(cause.clone()),
                            }
                        }
                    }
                }
            }
        }

        ui
    }
}

/// Apply a behavior to the UI for a given context.
fn apply_behavior(
    ui: &mut ModerationUi,
    cause: &ModerationCause,
    behavior: &ModerationBehavior,
    context: UiContext,
    downgraded: bool,
) {
    if downgraded {
        return;
    }
    if let Some(action) = behavior.get(context) {
        match action {
            BehaviorValue::Blur => ui.blurs.push(cause.clone()),
            BehaviorValue::Alert => ui.alerts.push(cause.clone()),
            BehaviorValue::Inform => ui.informs.push(cause.clone()),
        }
    }
}

/// Resolve label preference from user settings.
fn resolve_label_preference(
    label: &LabelData,
    label_def: &LabelValueDefinition,
    opts: &ModerationOpts,
) -> LabelPreference {
    // Non-configurable labels always use their default
    if !label_def.configurable {
        return label_def.default_setting;
    }

    // Adult labels with adult content disabled force hide
    if label_def.flags.contains(&LabelFlag::Adult) && !opts.prefs.adult_content_enabled {
        return LabelPreference::Hide;
    }

    // Check per-labeler preferences
    for labeler in &opts.prefs.labelers {
        if labeler.did == label.src {
            if let Some(pref) = labeler.labels.get(&label_def.identifier) {
                return *pref;
            }
        }
    }

    // Check global preferences
    if let Some(pref) = opts.prefs.labels.get(&label_def.identifier) {
        return *pref;
    }

    // Default
    label_def.default_setting
}

/// Calculate the priority of a label cause.
fn calculate_label_priority(
    label_def: &LabelValueDefinition,
    setting: LabelPreference,
    opts: &ModerationOpts,
) -> u8 {
    // No-override or adult with adult disabled → highest priority
    if label_def.flags.contains(&LabelFlag::NoOverride)
        || (label_def.flags.contains(&LabelFlag::Adult) && !opts.prefs.adult_content_enabled)
    {
        return 1;
    }

    if setting == LabelPreference::Hide {
        return 2;
    }

    // Check severity based on behavior definitions
    let has_profile_blur = label_def
        .behaviors
        .account
        .profile_view
        .map(|v| v == BehaviorValue::Blur)
        .unwrap_or(false)
        || label_def
            .behaviors
            .account
            .content_view
            .map(|v| v == BehaviorValue::Blur)
            .unwrap_or(false);

    if has_profile_blur {
        return 5;
    }

    let has_content_blur = label_def
        .behaviors
        .content
        .content_list
        .map(|v| v == BehaviorValue::Blur)
        .unwrap_or(false)
        || label_def
            .behaviors
            .content
            .content_media
            .map(|v| v == BehaviorValue::Blur)
            .unwrap_or(false);

    if has_content_blur {
        return 7;
    }

    8
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn default_opts() -> ModerationOpts {
        ModerationOpts {
            user_did: Some("did:plc:viewer".into()),
            prefs: ModerationPrefs {
                adult_content_enabled: true,
                labels: HashMap::new(),
                labelers: vec![],
                muted_words: vec![],
                hidden_posts: vec![],
            },
            label_defs: HashMap::new(),
        }
    }

    #[test]
    fn empty_decision_produces_empty_ui() {
        let decision = ModerationDecision::new("did:plc:test", false);
        let ui = decision.ui(UiContext::ContentList);
        assert!(!ui.filter());
        assert!(!ui.blur());
        assert!(!ui.alert());
        assert!(!ui.inform());
    }

    #[test]
    fn block_causes_filter_in_lists() {
        let mut decision = ModerationDecision::new("did:plc:test", false);
        decision.add_blocking(ModerationCauseSource::User);

        let ui = decision.ui(UiContext::ContentList);
        assert!(ui.filter());
        assert!(ui.blur());

        let ui = decision.ui(UiContext::ProfileList);
        assert!(ui.filter());
    }

    #[test]
    fn block_skipped_for_self() {
        let mut decision = ModerationDecision::new("did:plc:test", true);
        decision.add_blocking(ModerationCauseSource::User);

        let ui = decision.ui(UiContext::ContentList);
        assert!(!ui.filter());
        assert!(!ui.blur());
    }

    #[test]
    fn mute_causes_filter_and_blur() {
        let mut decision = ModerationDecision::new("did:plc:test", false);
        decision.add_muted(ModerationCauseSource::User);

        let ui = decision.ui(UiContext::ContentList);
        assert!(ui.filter());
        assert!(ui.blur());

        let ui = decision.ui(UiContext::ContentView);
        assert!(!ui.filter());
        assert!(ui.inform());
    }

    #[test]
    fn mute_word_only_filters_content_list() {
        let mut decision = ModerationDecision::new("did:plc:test", false);
        decision.add_mute_word(ModerationCauseSource::User);

        let ui = decision.ui(UiContext::ContentList);
        assert!(ui.filter());
        assert!(ui.blur());

        let ui = decision.ui(UiContext::ProfileList);
        assert!(!ui.filter());
    }

    #[test]
    fn hidden_post_filters() {
        let mut decision = ModerationDecision::new("did:plc:test", false);
        decision.add_hidden(ModerationCauseSource::User);

        let ui = decision.ui(UiContext::ContentList);
        assert!(ui.filter());
        assert!(ui.blur());
    }

    #[test]
    fn label_hide_filters_content() {
        let mut decision = ModerationDecision::new("did:plc:test", false);
        let opts = default_opts();

        decision.add_label(
            LabelData {
                src: "did:plc:labeler".into(),
                uri: "at://did:plc:test/app.bsky.feed.post/abc".into(),
                val: "!hide".into(),
                neg: None,
            },
            LabelTarget::Content,
            &opts,
        );

        let ui = decision.ui(UiContext::ContentList);
        assert!(ui.filter());
        assert!(ui.blur());
        assert!(ui.no_override);
    }

    #[test]
    fn label_warn_blurs_but_no_filter() {
        let mut decision = ModerationDecision::new("did:plc:test", false);
        let opts = default_opts();

        decision.add_label(
            LabelData {
                src: "did:plc:labeler".into(),
                uri: "at://did:plc:test/app.bsky.feed.post/abc".into(),
                val: "!warn".into(),
                neg: None,
            },
            LabelTarget::Content,
            &opts,
        );

        let ui = decision.ui(UiContext::ContentList);
        assert!(!ui.filter());
        assert!(ui.blur());
    }

    #[test]
    fn porn_label_with_adult_disabled_forces_hide() {
        let mut opts = default_opts();
        opts.prefs.adult_content_enabled = false;

        let mut decision = ModerationDecision::new("did:plc:test", false);
        decision.add_label(
            LabelData {
                src: "did:plc:labeler".into(),
                uri: "at://did:plc:test/app.bsky.feed.post/abc".into(),
                val: "porn".into(),
                neg: None,
            },
            LabelTarget::Content,
            &opts,
        );

        let ui = decision.ui(UiContext::ContentMedia);
        assert!(ui.blur());
        assert!(ui.no_override);
    }

    #[test]
    fn label_preference_ignore_skips_configurable() {
        let mut opts = default_opts();
        opts.prefs
            .labels
            .insert("nudity".into(), LabelPreference::Ignore);

        let mut decision = ModerationDecision::new("did:plc:test", false);
        decision.add_label(
            LabelData {
                src: "did:plc:labeler".into(),
                uri: "at://did:plc:test/app.bsky.feed.post/abc".into(),
                val: "nudity".into(),
                neg: None,
            },
            LabelTarget::Content,
            &opts,
        );

        assert!(decision.causes.is_empty());
    }

    #[test]
    fn merge_decisions() {
        let mut d1 = ModerationDecision::new("did:plc:test", false);
        d1.add_blocking(ModerationCauseSource::User);

        let mut d2 = ModerationDecision::new("did:plc:test", false);
        d2.add_muted(ModerationCauseSource::User);

        let merged = ModerationDecision::merge(vec![d1, d2]);
        assert_eq!(merged.causes.len(), 2);
    }

    #[test]
    fn downgrade_sets_all_causes() {
        let mut decision = ModerationDecision::new("did:plc:test", false);
        decision.add_blocking(ModerationCauseSource::User);
        decision.add_muted(ModerationCauseSource::User);
        decision.downgrade();

        for cause in &decision.causes {
            assert!(cause.is_downgraded());
        }

        // Downgraded causes don't apply behaviors
        let ui = decision.ui(UiContext::ContentList);
        assert!(!ui.blur());
        // But filters still apply
        assert!(ui.filter());
    }

    #[test]
    fn per_labeler_preference() {
        let mut opts = default_opts();
        opts.prefs.labelers.push(ModerationPrefsLabeler {
            did: "did:plc:my-labeler".into(),
            labels: {
                let mut m = HashMap::new();
                m.insert("porn".into(), LabelPreference::Warn);
                m
            },
        });

        let mut decision = ModerationDecision::new("did:plc:test", false);
        decision.add_label(
            LabelData {
                src: "did:plc:my-labeler".into(),
                uri: "at://did:plc:test/profile".into(),
                val: "porn".into(),
                neg: None,
            },
            LabelTarget::Content,
            &opts,
        );

        // porn with warn preference should have priority 7 (media blur, not hide)
        assert_eq!(decision.causes.len(), 1);
        assert_eq!(decision.causes[0].priority(), 7);
    }
}
