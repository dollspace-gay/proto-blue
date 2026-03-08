//! AT Protocol DAG-CBOR encoding/decoding with CID tag 42 support.
//!
//! This crate implements strict DAG-CBOR encoding and decoding for the
//! AT Protocol data model. CIDs are encoded using CBOR tag 42 with a
//! leading 0x00 byte prefix, and map keys are sorted by byte length
//! then lexicographically per the DAG-CBOR specification.
//!
//! # Examples
//!
//! ```
//! use proto_blue_lex_data::LexValue;
//! use proto_blue_lex_cbor::{encode, decode, cid_for_lex};
//! use std::collections::BTreeMap;
//!
//! // Encode a LexValue to DAG-CBOR bytes
//! let mut map = BTreeMap::new();
//! map.insert("hello".into(), LexValue::String("world".into()));
//! let value = LexValue::Map(map);
//! let bytes = encode(&value).unwrap();
//!
//! // Decode back
//! let decoded = decode(&bytes).unwrap();
//! assert_eq!(value, decoded);
//!
//! // Compute a CID for the value (SHA-256 + DAG-CBOR codec)
//! let cid = cid_for_lex(&value).unwrap();
//! assert!(cid.to_string().starts_with("bafyrei"));
//! ```

mod encoding;
mod error;

pub use encoding::{cid_for_lex, decode, decode_all, encode};
pub use error::CborError;
