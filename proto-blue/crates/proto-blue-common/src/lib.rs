//! AT Protocol shared utilities: TID generation, DID documents, retry, IPLD helpers.
//!
//! Merges the TS `common-web` and `common` packages into a single Rust crate.
//!
//! # Examples
//!
//! ```
//! use proto_blue_common::{grapheme_len, utf8_len, next_tid, SECOND, MINUTE, HOUR, DAY};
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

pub mod cancel;
pub mod did_doc;
pub mod fetch;
pub mod obfuscate;
pub mod retry;
pub mod strings;
pub mod tid_gen;
pub mod times;

pub use cancel::{CancelError, CancellationToken, cancellable, cancellable_infallible};
pub use did_doc::{
    DidDocument, Service, SigningKey, VerificationMethod, get_did, get_feed_gen_endpoint,
    get_handle, get_notif_endpoint, get_pds_endpoint, get_signing_did_key, get_signing_key,
    parse_did_document,
};
pub use fetch::{FetchError, FetchHandler, HttpHeaders, HttpMethod, HttpRequest, HttpResponse};
pub use obfuscate::{
    obfuscate_auth_header, obfuscate_basic, obfuscate_bearer, obfuscate_email, obfuscate_headers,
    obfuscate_jwt, obfuscate_token, obfuscate_word,
};
pub use retry::{RetryOptions, backoff_ms, retry, retry_all};
pub use strings::{grapheme_len, utf8_len};
pub use tid_gen::{next_tid, s32_decode, s32_encode};
pub use times::{DAY, HOUR, MINUTE, SECOND};
