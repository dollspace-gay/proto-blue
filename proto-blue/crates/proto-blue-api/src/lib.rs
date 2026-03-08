//! AT Protocol high-level API: agent, rich text, moderation, generated types.
//!
//! # Examples
//!
//! ```
//! use proto_blue_api::rich_text::{RichText, FacetFeature};
//!
//! // Create rich text with automatic facet detection
//! let mut rt = RichText::new(
//!     "Hello @alice.bsky.social! Check out https://bsky.app #atproto".to_string(),
//!     None,
//! );
//! rt.detect_facets();
//!
//! assert_eq!(rt.facets().len(), 3);
//!
//! // Iterate segments for rendering
//! let segments = rt.segments();
//! for seg in &segments {
//!     if let Some(facet) = &seg.facet {
//!         match &facet.features[0] {
//!             FacetFeature::Mention { did } => println!("@{}", did),
//!             FacetFeature::Link { uri } => println!("link: {}", uri),
//!             FacetFeature::Tag { tag } => println!("#{}", tag),
//!         }
//!     }
//! }
//! ```

pub mod agent;
pub mod moderation;
pub mod rich_text;

#[allow(
    non_snake_case,
    non_upper_case_globals,
    unused_imports,
    clippy::redundant_field_names
)]
pub mod generated;

// Re-export generated namespaces at crate root for cross-module references
pub use generated::app;
pub use generated::chat;
pub use generated::com;
pub use generated::tools;

// Re-export key types
pub use agent::{Agent, AgentError, Session};
pub use moderation::{ModerationDecision, ModerationOpts, ModerationUi};
pub use rich_text::{ByteSlice, Facet, FacetFeature, RichText};
