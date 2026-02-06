//! AT Protocol JSON <-> LexValue conversion with $link and $bytes encoding.
//!
//! In JSON representation:
//! - CIDs are encoded as `{"$link": "bafy..."}`
//! - Byte arrays are encoded as `{"$bytes": "<base64>"}`
//!
//! This crate provides bidirectional conversion between `serde_json::Value`
//! and `LexValue`, as well as string serialization/deserialization.
//!
//! # Examples
//!
//! ```
//! use atproto_lex_data::LexValue;
//! use atproto_lex_json::{lex_to_json, json_to_lex, lex_stringify, lex_parse};
//! use std::collections::BTreeMap;
//!
//! // Convert LexValue to JSON
//! let mut map = BTreeMap::new();
//! map.insert("text".into(), LexValue::String("Hello!".into()));
//! map.insert("count".into(), LexValue::Integer(42));
//! let value = LexValue::Map(map);
//!
//! let json = lex_to_json(&value);
//! assert_eq!(json["text"], "Hello!");
//! assert_eq!(json["count"], 42);
//!
//! // Convert back to LexValue
//! let roundtrip = json_to_lex(&json);
//! assert_eq!(value, roundtrip);
//!
//! // Stringify/parse for serialization
//! let s = lex_stringify(&value);
//! let parsed = lex_parse(&s).unwrap();
//! assert_eq!(value, parsed);
//! ```

mod conversion;
mod error;

pub use conversion::{json_to_lex, lex_parse, lex_stringify, lex_to_json};
pub use error::JsonError;
