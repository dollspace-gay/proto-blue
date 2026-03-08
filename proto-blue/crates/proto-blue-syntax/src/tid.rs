//! TID (Timestamp Identifier) validation and types.
//!
//! TIDs are 13-character base32-sortable timestamp identifiers.
//! See: <https://atproto.com/specs/record-key#record-key-type-tid>

use once_cell::sync::Lazy;
use regex::Regex;
use std::fmt;
use std::str::FromStr;

/// Exact length of a TID.
const TID_LENGTH: usize = 13;

/// Base32-sortable alphabet used by TIDs.
const S32_CHARSET: &[u8] = b"234567abcdefghijklmnopqrstuvwxyz";

static TID_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$").unwrap()
});

/// A validated TID (Timestamp Identifier).
///
/// TIDs are exactly 13 characters from the base32-sortable alphabet.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Tid(String);

/// Error returned when a TID string is invalid.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Invalid TID: {reason}")]
pub struct InvalidTidError {
    pub reason: String,
}

impl Tid {
    /// Create a new `Tid` from a string, validating the format.
    pub fn new(s: &str) -> Result<Self, InvalidTidError> {
        ensure_valid_tid(s)?;
        Ok(Tid(s.to_string()))
    }

    /// Check whether a string is a valid TID.
    pub fn is_valid(s: &str) -> bool {
        ensure_valid_tid(s).is_ok()
    }

    /// Return the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Decode the TID to its underlying microsecond timestamp.
    pub fn timestamp_micros(&self) -> u64 {
        s32_decode(&self.0[..11])
    }

    /// Encode a microsecond timestamp and clock ID into a TID.
    pub fn from_timestamp(timestamp_micros: u64, clock_id: u16) -> Self {
        // Upper 53 bits: timestamp, lower 10 bits: clock_id
        let tid_int = (timestamp_micros << 10) | (clock_id as u64 & 0x3FF);
        // Ensure top bit is 0
        let tid_int = tid_int & 0x7FFFFFFFFFFFFFFF;
        let encoded = s32_encode(tid_int);
        Tid(encoded)
    }
}

/// Encode a u64 to a 13-char base32-sortable string.
fn s32_encode(mut v: u64) -> String {
    let mut out = [b'2'; TID_LENGTH];
    for i in (0..TID_LENGTH).rev() {
        out[i] = S32_CHARSET[(v & 0x1F) as usize];
        v >>= 5;
    }
    String::from_utf8(out.to_vec()).unwrap()
}

/// Decode a base32-sortable string to a u64.
fn s32_decode(s: &str) -> u64 {
    let mut result: u64 = 0;
    for byte in s.bytes() {
        let val = match byte {
            b'2'..=b'7' => byte - b'2',
            b'a'..=b'z' => byte - b'a' + 6,
            _ => 0,
        };
        result = (result << 5) | val as u64;
    }
    result
}

fn ensure_valid_tid(s: &str) -> Result<(), InvalidTidError> {
    let err = |reason: &str| InvalidTidError {
        reason: reason.to_string(),
    };

    if s.len() != TID_LENGTH {
        return Err(err(&format!(
            "TID must be exactly {} characters, got {}",
            TID_LENGTH,
            s.len()
        )));
    }

    if !TID_REGEX.is_match(s) {
        return Err(err(
            "TID must match base32-sortable pattern (first char [234567abcdefghij], rest [234567abcdefghijklmnopqrstuvwxyz])",
        ));
    }

    Ok(())
}

impl fmt::Display for Tid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Tid {
    type Err = InvalidTidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Tid::new(s)
    }
}

impl AsRef<str> for Tid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl serde::Serialize for Tid {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Tid {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Tid::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_tids() {
        assert!(Tid::new("3jui7kd54zh2y").is_ok());
        assert!(Tid::new("2222222222222").is_ok());
        assert!(Tid::new("jzzzzzzzzzzzy").is_ok()); // 'j' is the last valid first char
        assert!(Tid::new("kzzzzzzzzzzzy").is_err()); // 'k' is NOT valid as first char
    }

    #[test]
    fn invalid_tids() {
        assert!(Tid::new("").is_err());
        assert!(Tid::new("too_short").is_err());
        assert!(Tid::new("0000000000000").is_err()); // '0' not in charset
        assert!(Tid::new("3jui7kd54zh2yX").is_err()); // too long
    }

    #[test]
    fn length_check() {
        assert!(Tid::new("abcdefghijklm").is_ok());
        assert!(Tid::new("abcdefghijkl").is_err()); // 12 chars
        assert!(Tid::new("abcdefghijklmn").is_err()); // 14 chars
    }

    #[test]
    fn from_timestamp_roundtrip() {
        let ts: u64 = 1_700_000_000_000_000; // microseconds
        let clock_id: u16 = 42;
        let tid = Tid::from_timestamp(ts, clock_id);
        assert_eq!(tid.as_str().len(), 13);
        assert!(Tid::is_valid(tid.as_str()));
    }

    #[test]
    fn s32_encode_decode() {
        let val: u64 = 12345678;
        let encoded = s32_encode(val);
        let decoded = s32_decode(&encoded);
        assert_eq!(decoded, val);
    }
}
