//! Moderation type definitions.

use serde::{Deserialize, Serialize};

/// User preference for how a label should be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LabelPreference {
    Ignore,
    Warn,
    Hide,
}

/// UI context where moderation decisions are applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UiContext {
    ProfileList,
    ProfileView,
    ContentList,
    ContentView,
    ContentMedia,
    Avatar,
    Banner,
    DisplayName,
}

/// What a label blurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LabelBlurs {
    Content,
    Media,
    None,
}

/// Label severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LabelSeverity {
    Alert,
    Inform,
    None,
}

/// Flags on a label value definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelFlag {
    NoOverride,
    Adult,
    Unauthed,
    NoSelf,
}

/// A UI action that can be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehaviorValue {
    Blur,
    Alert,
    Inform,
}

/// Per-context behavior map for a label.
#[derive(Debug, Clone, Default)]
pub struct ModerationBehavior {
    pub profile_list: Option<BehaviorValue>,
    pub profile_view: Option<BehaviorValue>,
    pub content_list: Option<BehaviorValue>,
    pub content_view: Option<BehaviorValue>,
    pub content_media: Option<BehaviorValue>,
    pub avatar: Option<BehaviorValue>,
    pub banner: Option<BehaviorValue>,
    pub display_name: Option<BehaviorValue>,
}

impl ModerationBehavior {
    pub fn get(&self, ctx: UiContext) -> Option<BehaviorValue> {
        match ctx {
            UiContext::ProfileList => self.profile_list,
            UiContext::ProfileView => self.profile_view,
            UiContext::ContentList => self.content_list,
            UiContext::ContentView => self.content_view,
            UiContext::ContentMedia => self.content_media,
            UiContext::Avatar => self.avatar,
            UiContext::Banner => self.banner,
            UiContext::DisplayName => self.display_name,
        }
    }
}

/// An interpreted label value definition.
#[derive(Debug, Clone)]
pub struct LabelValueDefinition {
    pub identifier: String,
    pub configurable: bool,
    pub default_setting: LabelPreference,
    pub flags: Vec<LabelFlag>,
    pub severity: LabelSeverity,
    pub blurs: LabelBlurs,
    pub behaviors: LabelBehaviors,
}

/// Behaviors for different label targets.
#[derive(Debug, Clone)]
pub struct LabelBehaviors {
    pub account: ModerationBehavior,
    pub profile: ModerationBehavior,
    pub content: ModerationBehavior,
}

/// Where the moderation cause originated.
#[derive(Debug, Clone)]
pub enum ModerationCauseSource {
    User,
    List { uri: String, name: String },
    Labeler { did: String },
}

/// The target a label was applied to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelTarget {
    Account,
    Profile,
    Content,
}

/// A single cause for a moderation decision.
#[derive(Debug, Clone)]
pub enum ModerationCause {
    Blocking {
        source: ModerationCauseSource,
        priority: u8,
        downgraded: bool,
    },
    BlockedBy {
        source: ModerationCauseSource,
        priority: u8,
        downgraded: bool,
    },
    BlockOther {
        source: ModerationCauseSource,
        priority: u8,
        downgraded: bool,
    },
    Label {
        source: ModerationCauseSource,
        label: LabelData,
        label_def: LabelValueDefinition,
        target: LabelTarget,
        setting: LabelPreference,
        no_override: bool,
        priority: u8,
        downgraded: bool,
    },
    Muted {
        source: ModerationCauseSource,
        priority: u8,
        downgraded: bool,
    },
    MuteWord {
        source: ModerationCauseSource,
        priority: u8,
        downgraded: bool,
    },
    Hidden {
        source: ModerationCauseSource,
        priority: u8,
        downgraded: bool,
    },
}

impl ModerationCause {
    pub fn priority(&self) -> u8 {
        match self {
            Self::Blocking { priority, .. }
            | Self::BlockedBy { priority, .. }
            | Self::BlockOther { priority, .. }
            | Self::Label { priority, .. }
            | Self::Muted { priority, .. }
            | Self::MuteWord { priority, .. }
            | Self::Hidden { priority, .. } => *priority,
        }
    }

    pub fn is_downgraded(&self) -> bool {
        match self {
            Self::Blocking { downgraded, .. }
            | Self::BlockedBy { downgraded, .. }
            | Self::BlockOther { downgraded, .. }
            | Self::Label { downgraded, .. }
            | Self::Muted { downgraded, .. }
            | Self::MuteWord { downgraded, .. }
            | Self::Hidden { downgraded, .. } => *downgraded,
        }
    }

    pub fn set_downgraded(&mut self) {
        match self {
            Self::Blocking { downgraded, .. }
            | Self::BlockedBy { downgraded, .. }
            | Self::BlockOther { downgraded, .. }
            | Self::Label { downgraded, .. }
            | Self::Muted { downgraded, .. }
            | Self::MuteWord { downgraded, .. }
            | Self::Hidden { downgraded, .. } => *downgraded = true,
        }
    }
}

/// Minimal label data for moderation decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelData {
    pub src: String,
    pub uri: String,
    pub val: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neg: Option<bool>,
}

/// A muted word rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutedWord {
    pub value: String,
    pub targets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Per-labeler moderation preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModerationPrefsLabeler {
    pub did: String,
    pub labels: std::collections::HashMap<String, LabelPreference>,
}

/// User moderation preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModerationPrefs {
    pub adult_content_enabled: bool,
    pub labels: std::collections::HashMap<String, LabelPreference>,
    pub labelers: Vec<ModerationPrefsLabeler>,
    pub muted_words: Vec<MutedWord>,
    pub hidden_posts: Vec<String>,
}

/// Top-level moderation options passed to the decision engine.
#[derive(Debug, Clone)]
pub struct ModerationOpts {
    pub user_did: Option<String>,
    pub prefs: ModerationPrefs,
    pub label_defs: std::collections::HashMap<String, Vec<LabelValueDefinition>>,
}

/// The output of applying a moderation decision to a UI context.
#[derive(Debug, Clone, Default)]
pub struct ModerationUi {
    pub no_override: bool,
    pub filters: Vec<ModerationCause>,
    pub blurs: Vec<ModerationCause>,
    pub alerts: Vec<ModerationCause>,
    pub informs: Vec<ModerationCause>,
}

impl ModerationUi {
    pub fn filter(&self) -> bool {
        !self.filters.is_empty()
    }
    pub fn blur(&self) -> bool {
        !self.blurs.is_empty()
    }
    pub fn alert(&self) -> bool {
        !self.alerts.is_empty()
    }
    pub fn inform(&self) -> bool {
        !self.informs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_preference_serde() {
        let pref = LabelPreference::Hide;
        let json = serde_json::to_string(&pref).unwrap();
        assert_eq!(json, "\"hide\"");
        let parsed: LabelPreference = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, LabelPreference::Hide);
    }

    #[test]
    fn moderation_ui_helpers() {
        let mut ui = ModerationUi::default();
        assert!(!ui.filter());
        assert!(!ui.blur());
        assert!(!ui.alert());
        assert!(!ui.inform());

        ui.filters.push(ModerationCause::Hidden {
            source: ModerationCauseSource::User,
            priority: 6,
            downgraded: false,
        });
        assert!(ui.filter());
    }

    #[test]
    fn cause_priority_and_downgrade() {
        let mut cause = ModerationCause::Muted {
            source: ModerationCauseSource::User,
            priority: 6,
            downgraded: false,
        };
        assert_eq!(cause.priority(), 6);
        assert!(!cause.is_downgraded());
        cause.set_downgraded();
        assert!(cause.is_downgraded());
    }

    #[test]
    fn muted_word_serde() {
        let word = MutedWord {
            value: "test".into(),
            targets: vec!["content".into()],
            actor_target: Some("exclude-following".into()),
            expires_at: None,
        };
        let json = serde_json::to_string(&word).unwrap();
        assert!(json.contains("\"actorTarget\""));
        let parsed: MutedWord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.value, "test");
    }

    #[test]
    fn behavior_get_context() {
        let behavior = ModerationBehavior {
            content_list: Some(BehaviorValue::Blur),
            content_view: Some(BehaviorValue::Alert),
            ..Default::default()
        };
        assert_eq!(
            behavior.get(UiContext::ContentList),
            Some(BehaviorValue::Blur)
        );
        assert_eq!(
            behavior.get(UiContext::ContentView),
            Some(BehaviorValue::Alert)
        );
        assert_eq!(behavior.get(UiContext::Avatar), None);
    }
}
