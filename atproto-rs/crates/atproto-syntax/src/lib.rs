//! AT Protocol identifier types with validation.
//!
//! Provides validated newtypes for all AT Protocol identifiers:
//! DID, Handle, NSID, AT-URI, TID, RecordKey, Datetime, and AtIdentifier.
//!
//! # Examples
//!
//! ```
//! use atproto_syntax::{Did, Handle, Nsid, AtUri, Tid, RecordKey};
//!
//! // Parse and validate a DID
//! let did = Did::new("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
//! assert_eq!(did.method(), "plc");
//!
//! // Parse a handle
//! let handle = Handle::new("alice.bsky.social").unwrap();
//! assert_eq!(handle.to_string(), "alice.bsky.social");
//!
//! // Parse an NSID
//! let nsid = Nsid::new("app.bsky.feed.post").unwrap();
//! assert_eq!(nsid.authority(), "app.bsky.feed");
//! assert_eq!(nsid.name(), "post");
//!
//! // Parse an AT-URI
//! let uri = AtUri::new("at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/abc123").unwrap();
//! assert_eq!(uri.collection(), Some("app.bsky.feed.post"));
//! assert_eq!(uri.rkey(), Some("abc123"));
//!
//! // Generate a TID from a timestamp
//! let tid = Tid::from_timestamp(1704067200_000_000, 0);
//! assert_eq!(tid.to_string().len(), 13);
//!
//! // Validate a record key
//! let rkey = RecordKey::new("self").unwrap();
//! assert!(RecordKey::new(".").is_err()); // "." is not allowed
//! ```

mod at_identifier;
mod aturi;
mod datetime;
mod did;
mod handle;
mod language;
mod nsid;
mod recordkey;
mod tid;

pub use at_identifier::{AtIdentifier, InvalidAtIdentifierError};
pub use aturi::{AtUri, InvalidAtUriError};
pub use datetime::{Datetime, InvalidDatetimeError, normalize_datetime};
pub use did::{Did, InvalidDidError};
pub use handle::{DISALLOWED_TLDS, Handle, InvalidHandleError};
pub use language::is_valid_language;
pub use nsid::{InvalidNsidError, Nsid};
pub use recordkey::{InvalidRecordKeyError, RecordKey};
pub use tid::{InvalidTidError, Tid};
