//! AT Protocol shared utilities: TID generation, DID documents, retry, IPLD helpers.
//!
//! Merges the TS `common-web` and `common` packages into a single Rust crate.
//!
//! # Examples
//!
//! ```
//! use atproto_common::{grapheme_len, utf8_len, next_tid, SECOND, MINUTE, HOUR, DAY};
//!
//! // Grapheme-aware string length
//! assert_eq!(grapheme_len("Hello"), 5);
//! assert_eq!(utf8_len("Hello"), 5);
//!
//! // Time constants (in milliseconds)
//! assert_eq!(SECOND, 1000);
//! assert_eq!(MINUTE, 60_000);
//! assert_eq!(HOUR, 3_600_000);
//! assert_eq!(DAY, 86_400_000);
//!
//! // Generate a TID (timestamp-based ID)
//! let tid = next_tid(None);
//! assert_eq!(tid.to_string().len(), 13);
//! ```

pub mod did_doc;
pub mod retry;
pub mod strings;
pub mod tid_gen;
pub mod times;

pub use did_doc::{
    DidDocument, SigningKey, get_did, get_feed_gen_endpoint, get_handle, get_notif_endpoint,
    get_pds_endpoint, get_signing_did_key, get_signing_key, parse_did_document,
};
pub use retry::{RetryOptions, backoff_ms, retry, retry_all};
pub use strings::{grapheme_len, utf8_len};
pub use tid_gen::next_tid;
pub use times::{DAY, HOUR, MINUTE, SECOND};
