//! Parse and format MST keys of the form `<nsid>/<rkey>`.
//!
//! atproto repositories key their records by joining the collection
//! NSID and the record key with a single `/`. These helpers handle the
//! split and join while validating the NSID portion — mirrors TS
//! `parseDataKey` / `formatDataKey`.

use proto_blue_syntax::{Nsid, RecordKey};
use thiserror::Error;

/// A parsed data key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataKey {
    pub collection: String,
    pub rkey: String,
}

/// Error returned when a data key can't be parsed.
#[derive(Debug, Clone, Error)]
pub enum DataKeyError {
    #[error("data key missing '/': {0}")]
    MissingSeparator(String),
    #[error("invalid NSID in data key: {0}")]
    InvalidNsid(String),
    #[error("invalid record key in data key: {0}")]
    InvalidRecordKey(String),
}

/// Split an MST key into `(collection, rkey)` and validate both halves.
pub fn parse_data_key(key: &str) -> Result<DataKey, DataKeyError> {
    let (coll, rkey) = key
        .split_once('/')
        .ok_or_else(|| DataKeyError::MissingSeparator(key.to_string()))?;
    Nsid::new(coll).map_err(|e| DataKeyError::InvalidNsid(e.to_string()))?;
    RecordKey::new(rkey).map_err(|e| DataKeyError::InvalidRecordKey(e.to_string()))?;
    Ok(DataKey {
        collection: coll.to_string(),
        rkey: rkey.to_string(),
    })
}

/// Join an NSID and record key into an MST key. Does not validate —
/// assumes inputs are already valid (typical usage is building from
/// known-good `Nsid` / `RecordKey` values).
pub fn format_data_key(collection: &str, rkey: &str) -> String {
    format!("{collection}/{rkey}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_key() {
        let k = parse_data_key("app.bsky.feed.post/abc123").unwrap();
        assert_eq!(k.collection, "app.bsky.feed.post");
        assert_eq!(k.rkey, "abc123");
    }

    #[test]
    fn parse_missing_separator_errors() {
        let err = parse_data_key("app.bsky.feed.post").unwrap_err();
        assert!(matches!(err, DataKeyError::MissingSeparator(_)));
    }

    #[test]
    fn parse_invalid_nsid_errors() {
        let err = parse_data_key("not-an-nsid/abc").unwrap_err();
        assert!(matches!(err, DataKeyError::InvalidNsid(_)));
    }

    #[test]
    fn parse_invalid_rkey_errors() {
        let err = parse_data_key("app.bsky.feed.post/.").unwrap_err();
        assert!(matches!(err, DataKeyError::InvalidRecordKey(_)));
    }

    #[test]
    fn format_round_trips() {
        let k = format_data_key("app.bsky.feed.post", "abc123");
        assert_eq!(k, "app.bsky.feed.post/abc123");
        let parsed = parse_data_key(&k).unwrap();
        assert_eq!(parsed.collection, "app.bsky.feed.post");
        assert_eq!(parsed.rkey, "abc123");
    }
}
