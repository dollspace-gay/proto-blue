//! Moderation engine for AT Protocol.
//!
//! Implements label-based content moderation, mute word matching,
//! and priority-based decision aggregation for UI contexts.

pub mod decision;
pub mod labels;
pub mod mutewords;
pub mod types;

pub use decision::ModerationDecision;
pub use labels::{find_label_def, known_labels};
pub use mutewords::{MutedWordMatch, check_muted_words};
pub use types::*;
