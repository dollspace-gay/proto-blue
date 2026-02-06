//! Known label definitions and behavior mappings.

use super::types::*;

/// Predefined behavior for block causes.
pub fn block_behavior() -> ModerationBehavior {
    ModerationBehavior {
        profile_list: Some(BehaviorValue::Blur),
        profile_view: Some(BehaviorValue::Alert),
        content_list: Some(BehaviorValue::Blur),
        content_view: Some(BehaviorValue::Blur),
        avatar: Some(BehaviorValue::Blur),
        banner: Some(BehaviorValue::Blur),
        ..Default::default()
    }
}

/// Predefined behavior for mute causes.
pub fn mute_behavior() -> ModerationBehavior {
    ModerationBehavior {
        profile_list: Some(BehaviorValue::Inform),
        profile_view: Some(BehaviorValue::Alert),
        content_list: Some(BehaviorValue::Blur),
        content_view: Some(BehaviorValue::Inform),
        ..Default::default()
    }
}

/// Predefined behavior for mute word causes.
pub fn mute_word_behavior() -> ModerationBehavior {
    ModerationBehavior {
        content_list: Some(BehaviorValue::Blur),
        content_view: Some(BehaviorValue::Blur),
        ..Default::default()
    }
}

/// Predefined behavior for hidden post causes.
pub fn hide_behavior() -> ModerationBehavior {
    ModerationBehavior {
        content_list: Some(BehaviorValue::Blur),
        content_view: Some(BehaviorValue::Blur),
        ..Default::default()
    }
}

/// Build the list of known (system) label definitions.
pub fn known_labels() -> Vec<LabelValueDefinition> {
    vec![
        // Imperative labels (non-configurable)
        LabelValueDefinition {
            identifier: "!hide".into(),
            configurable: false,
            default_setting: LabelPreference::Hide,
            flags: vec![LabelFlag::NoOverride, LabelFlag::NoSelf],
            severity: LabelSeverity::Alert,
            blurs: LabelBlurs::Content,
            behaviors: LabelBehaviors {
                account: ModerationBehavior {
                    profile_list: Some(BehaviorValue::Blur),
                    profile_view: Some(BehaviorValue::Blur),
                    content_list: Some(BehaviorValue::Blur),
                    content_view: Some(BehaviorValue::Blur),
                    avatar: Some(BehaviorValue::Blur),
                    banner: Some(BehaviorValue::Blur),
                    display_name: Some(BehaviorValue::Blur),
                    ..Default::default()
                },
                profile: ModerationBehavior {
                    avatar: Some(BehaviorValue::Blur),
                    banner: Some(BehaviorValue::Blur),
                    display_name: Some(BehaviorValue::Blur),
                    ..Default::default()
                },
                content: ModerationBehavior {
                    content_list: Some(BehaviorValue::Blur),
                    content_view: Some(BehaviorValue::Blur),
                    ..Default::default()
                },
            },
        },
        LabelValueDefinition {
            identifier: "!warn".into(),
            configurable: false,
            default_setting: LabelPreference::Warn,
            flags: vec![LabelFlag::NoSelf],
            severity: LabelSeverity::None,
            blurs: LabelBlurs::Content,
            behaviors: LabelBehaviors {
                account: ModerationBehavior {
                    profile_list: Some(BehaviorValue::Blur),
                    profile_view: Some(BehaviorValue::Blur),
                    content_list: Some(BehaviorValue::Blur),
                    content_view: Some(BehaviorValue::Blur),
                    avatar: Some(BehaviorValue::Blur),
                    banner: Some(BehaviorValue::Blur),
                    display_name: Some(BehaviorValue::Blur),
                    ..Default::default()
                },
                profile: ModerationBehavior {
                    avatar: Some(BehaviorValue::Blur),
                    banner: Some(BehaviorValue::Blur),
                    display_name: Some(BehaviorValue::Blur),
                    ..Default::default()
                },
                content: ModerationBehavior {
                    content_list: Some(BehaviorValue::Blur),
                    content_view: Some(BehaviorValue::Blur),
                    ..Default::default()
                },
            },
        },
        LabelValueDefinition {
            identifier: "!no-unauthenticated".into(),
            configurable: false,
            default_setting: LabelPreference::Hide,
            flags: vec![LabelFlag::NoOverride, LabelFlag::Unauthed],
            severity: LabelSeverity::None,
            blurs: LabelBlurs::Content,
            behaviors: LabelBehaviors {
                account: ModerationBehavior {
                    profile_list: Some(BehaviorValue::Blur),
                    profile_view: Some(BehaviorValue::Blur),
                    content_list: Some(BehaviorValue::Blur),
                    content_view: Some(BehaviorValue::Blur),
                    avatar: Some(BehaviorValue::Blur),
                    banner: Some(BehaviorValue::Blur),
                    display_name: Some(BehaviorValue::Blur),
                    ..Default::default()
                },
                profile: ModerationBehavior {
                    avatar: Some(BehaviorValue::Blur),
                    banner: Some(BehaviorValue::Blur),
                    display_name: Some(BehaviorValue::Blur),
                    ..Default::default()
                },
                content: ModerationBehavior {
                    content_list: Some(BehaviorValue::Blur),
                    content_view: Some(BehaviorValue::Blur),
                    ..Default::default()
                },
            },
        },
        // Configurable content labels
        LabelValueDefinition {
            identifier: "porn".into(),
            configurable: true,
            default_setting: LabelPreference::Hide,
            flags: vec![LabelFlag::Adult],
            severity: LabelSeverity::None,
            blurs: LabelBlurs::Media,
            behaviors: media_label_behaviors(),
        },
        LabelValueDefinition {
            identifier: "sexual".into(),
            configurable: true,
            default_setting: LabelPreference::Warn,
            flags: vec![LabelFlag::Adult],
            severity: LabelSeverity::None,
            blurs: LabelBlurs::Media,
            behaviors: media_label_behaviors(),
        },
        LabelValueDefinition {
            identifier: "nudity".into(),
            configurable: true,
            default_setting: LabelPreference::Ignore,
            flags: vec![],
            severity: LabelSeverity::None,
            blurs: LabelBlurs::Media,
            behaviors: media_label_behaviors(),
        },
        LabelValueDefinition {
            identifier: "graphic-media".into(),
            configurable: true,
            default_setting: LabelPreference::Warn,
            flags: vec![LabelFlag::Adult],
            severity: LabelSeverity::None,
            blurs: LabelBlurs::Media,
            behaviors: media_label_behaviors(),
        },
        // Legacy alias
        LabelValueDefinition {
            identifier: "gore".into(),
            configurable: true,
            default_setting: LabelPreference::Warn,
            flags: vec![LabelFlag::Adult],
            severity: LabelSeverity::None,
            blurs: LabelBlurs::Media,
            behaviors: media_label_behaviors(),
        },
    ]
}

/// Standard behaviors for media-blur labels (porn, sexual, nudity, graphic-media).
fn media_label_behaviors() -> LabelBehaviors {
    LabelBehaviors {
        account: ModerationBehavior {
            avatar: Some(BehaviorValue::Blur),
            banner: Some(BehaviorValue::Blur),
            ..Default::default()
        },
        profile: ModerationBehavior {
            avatar: Some(BehaviorValue::Blur),
            banner: Some(BehaviorValue::Blur),
            ..Default::default()
        },
        content: ModerationBehavior {
            content_media: Some(BehaviorValue::Blur),
            ..Default::default()
        },
    }
}

/// Look up a label definition by identifier from known labels + custom defs.
pub fn find_label_def(
    identifier: &str,
    custom_defs: &std::collections::HashMap<String, Vec<LabelValueDefinition>>,
) -> Option<LabelValueDefinition> {
    // Check known labels first
    for def in known_labels() {
        if def.identifier == identifier {
            return Some(def);
        }
    }
    // Check custom labeler definitions
    for defs in custom_defs.values() {
        for def in defs {
            if def.identifier == identifier {
                return Some(def.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_labels_defined() {
        let labels = known_labels();
        assert!(labels.len() >= 8);
        let ids: Vec<&str> = labels.iter().map(|l| l.identifier.as_str()).collect();
        assert!(ids.contains(&"!hide"));
        assert!(ids.contains(&"!warn"));
        assert!(ids.contains(&"porn"));
        assert!(ids.contains(&"nudity"));
    }

    #[test]
    fn find_known_label() {
        let defs = std::collections::HashMap::new();
        let hide = find_label_def("!hide", &defs).unwrap();
        assert!(!hide.configurable);
        assert!(hide.flags.contains(&LabelFlag::NoOverride));

        let porn = find_label_def("porn", &defs).unwrap();
        assert!(porn.configurable);
        assert!(porn.flags.contains(&LabelFlag::Adult));
        assert_eq!(porn.default_setting, LabelPreference::Hide);
    }

    #[test]
    fn find_custom_label() {
        let mut defs = std::collections::HashMap::new();
        defs.insert(
            "did:plc:custom-labeler".into(),
            vec![LabelValueDefinition {
                identifier: "custom-bad".into(),
                configurable: true,
                default_setting: LabelPreference::Warn,
                flags: vec![],
                severity: LabelSeverity::Alert,
                blurs: LabelBlurs::Content,
                behaviors: LabelBehaviors {
                    account: ModerationBehavior::default(),
                    profile: ModerationBehavior::default(),
                    content: ModerationBehavior {
                        content_list: Some(BehaviorValue::Blur),
                        content_view: Some(BehaviorValue::Alert),
                        ..Default::default()
                    },
                },
            }],
        );
        let found = find_label_def("custom-bad", &defs).unwrap();
        assert_eq!(found.severity, LabelSeverity::Alert);
    }

    #[test]
    fn unknown_label_returns_none() {
        let defs = std::collections::HashMap::new();
        assert!(find_label_def("nonexistent", &defs).is_none());
    }

    #[test]
    fn behavior_presets() {
        let b = block_behavior();
        assert_eq!(b.get(UiContext::ContentList), Some(BehaviorValue::Blur));
        assert_eq!(b.get(UiContext::ProfileView), Some(BehaviorValue::Alert));

        let m = mute_behavior();
        assert_eq!(m.get(UiContext::ContentList), Some(BehaviorValue::Blur));
        assert_eq!(m.get(UiContext::ContentView), Some(BehaviorValue::Inform));

        let mw = mute_word_behavior();
        assert_eq!(mw.get(UiContext::ContentList), Some(BehaviorValue::Blur));
        assert_eq!(mw.get(UiContext::Avatar), None);
    }
}
