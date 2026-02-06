//! AT Protocol core data types: CID, LexValue, BlobRef.
//!
//! This crate provides the foundational IPLD/Lexicon data model types used throughout
//! the AT Protocol. These include content identifiers (CIDs), the recursive LexValue
//! type, and blob references.
//!
//! # Examples
//!
//! ```
//! use atproto_lex_data::{Cid, LexValue};
//! use std::collections::BTreeMap;
//!
//! // Parse a CID from a base32 multibase string
//! let cid: Cid = "bafyreif75igchtxu635l343pgwjxxtfdv5ngckj3khwzzpss4cv6dwvyeq".parse().unwrap();
//! assert_eq!(cid.codec, atproto_lex_data::CBOR_CODEC);
//!
//! // Build a LexValue map (BTreeMap for deterministic ordering)
//! let mut map = BTreeMap::new();
//! map.insert("name".into(), LexValue::String("Alice".into()));
//! map.insert("age".into(), LexValue::Integer(30));
//! let value = LexValue::Map(map);
//!
//! // LexValue supports nested structures
//! if let LexValue::Map(m) = &value {
//!     assert_eq!(m.get("name"), Some(&LexValue::String("Alice".into())));
//! }
//! ```

mod blob;
mod cid;
mod lex_value;

pub use blob::BlobRef;
pub use cid::{CBOR_CODEC, Cid, CidError, RAW_CODEC, SHA2_256, SHA2_512};
pub use lex_value::LexValue;
