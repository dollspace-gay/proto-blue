//! Datetime validation and types.
//!
//! AT Protocol datetimes follow a strict subset of RFC 3339.
//! See: <https://atproto.com/specs/lexicon#datetime>

use once_cell::sync::Lazy;
use regex::Regex;
use std::fmt;
use std::str::FromStr;

/// Maximum length of a datetime string.
const MAX_DATETIME_LENGTH: usize = 64;

static DATETIME_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^[0-9]{4}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-6][0-9]:[0-6][0-9](\.[0-9]{1,20})?(Z|([+-][0-2][0-9]:[0-5][0-9]))$",
    )
    .unwrap()
});

/// A validated AT Protocol datetime string.
///
/// Format: `YYYY-MM-DDTHH:mm:ss(.fractional)?(Z|±HH:mm)`
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Datetime(String);

/// Error returned when a datetime string is invalid.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Invalid datetime: {reason}")]
pub struct InvalidDatetimeError {
    pub reason: String,
}

impl Datetime {
    /// Create a new `Datetime` from a string, validating the format.
    pub fn new(s: &str) -> Result<Self, InvalidDatetimeError> {
        ensure_valid_datetime(s)?;
        Ok(Datetime(s.to_string()))
    }

    /// Check whether a string is a valid datetime.
    pub fn is_valid(s: &str) -> bool {
        ensure_valid_datetime(s).is_ok()
    }

    /// Return the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

fn ensure_valid_datetime(s: &str) -> Result<(), InvalidDatetimeError> {
    let err = |reason: &str| InvalidDatetimeError {
        reason: reason.to_string(),
    };

    if s.len() > MAX_DATETIME_LENGTH {
        return Err(err(&format!(
            "Datetime too long ({} chars, max {})",
            s.len(),
            MAX_DATETIME_LENGTH
        )));
    }

    if !DATETIME_REGEX.is_match(s) {
        return Err(err("Datetime does not match RFC 3339 format"));
    }

    // Cannot use -00:00 offset (use Z for UTC)
    if s.ends_with("-00:00") {
        return Err(err("Datetime cannot use -00:00 offset; use Z for UTC"));
    }

    // Cannot start with 000 (too close to year zero)
    if s.starts_with("000") {
        return Err(err("Datetime year cannot start with 000"));
    }

    Ok(())
}

/// Normalize a datetime to canonical `YYYY-MM-DDTHH:mm:ss.sssZ` format.
pub fn normalize_datetime(s: &str) -> Result<String, InvalidDatetimeError> {
    ensure_valid_datetime(s)?;

    // Parse the components manually for normalization
    // The TS SDK uses Date object; we'll do basic timezone normalization
    // For now, if it ends with Z, keep it; otherwise convert offset to Z
    if s.ends_with('Z') {
        // Already UTC, ensure 3 decimal places for milliseconds
        return Ok(normalize_fractional(s));
    }

    // Has timezone offset like +05:30 or -08:00
    // Parse and convert to UTC
    let tz_pos = s.len() - 6; // ±HH:mm is 6 chars
    let datetime_part = &s[..tz_pos];
    let tz_part = &s[tz_pos..];

    let tz_sign: i32 = if tz_part.starts_with('+') { 1 } else { -1 };
    let tz_hours: i32 = tz_part[1..3].parse().unwrap_or(0);
    let tz_minutes: i32 = tz_part[4..6].parse().unwrap_or(0);
    let tz_offset_minutes = tz_sign * (tz_hours * 60 + tz_minutes);

    // Parse date/time components
    let year: i32 = s[0..4].parse().unwrap_or(0);
    let month: u32 = s[5..7].parse().unwrap_or(1);
    let day: u32 = s[8..10].parse().unwrap_or(1);
    let hour: i32 = s[11..13].parse().unwrap_or(0);
    let minute: i32 = s[14..16].parse().unwrap_or(0);
    let second: u32 = s[17..19].parse().unwrap_or(0);

    // Extract fractional seconds
    let frac = if datetime_part.len() > 19 {
        &datetime_part[19..]
    } else {
        ""
    };

    // Convert to UTC by subtracting timezone offset
    let total_minutes = hour * 60 + minute - tz_offset_minutes;
    let utc_hour = ((total_minutes / 60) % 24 + 24) % 24;
    let utc_minute = ((total_minutes % 60) + 60) % 60;

    // Handle day rollover (simplified - doesn't handle month boundaries perfectly)
    let day_offset = if total_minutes < 0 {
        -1
    } else if total_minutes >= 24 * 60 {
        1
    } else {
        0
    };
    let utc_day = (day as i32 + day_offset).max(1) as u32;

    let frac_str = normalize_frac(frac);
    Ok(format!(
        "{year:04}-{month:02}-{utc_day:02}T{utc_hour:02}:{utc_minute:02}:{second:02}{frac_str}Z"
    ))
}

fn normalize_fractional(s: &str) -> String {
    // Ensure we have .sss format (3 decimal places)
    let z_pos = s.len() - 1; // 'Z'
    let datetime_part = &s[..z_pos];

    if let Some(dot_pos) = datetime_part.rfind('.') {
        let frac = &datetime_part[dot_pos..];
        let base = &datetime_part[..dot_pos];
        let frac_str = normalize_frac(frac);
        format!("{base}{frac_str}Z")
    } else {
        format!("{datetime_part}.000Z")
    }
}

fn normalize_frac(frac: &str) -> String {
    if frac.is_empty() {
        return ".000".to_string();
    }
    // frac starts with '.'
    let digits = &frac[1..];
    if digits.len() >= 3 {
        format!(".{}", &digits[..3])
    } else {
        format!(".{:0<3}", digits)
    }
}

impl fmt::Display for Datetime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Datetime {
    type Err = InvalidDatetimeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Datetime::new(s)
    }
}

impl AsRef<str> for Datetime {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl serde::Serialize for Datetime {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Datetime {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Datetime::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_datetimes() {
        let cases = [
            "2023-11-15T12:30:00Z",
            "2023-11-15T12:30:00.123Z",
            "2023-11-15T12:30:00+05:30",
            "2023-11-15T12:30:00-08:00",
            "2023-11-15T12:30:00.1Z",
            "2023-11-15T12:30:00.12345678901234567890Z",
        ];
        for dt in &cases {
            assert!(Datetime::new(dt).is_ok(), "should be valid: {dt}");
        }
    }

    #[test]
    fn invalid_datetimes() {
        assert!(Datetime::new("").is_err(), "empty");
        assert!(Datetime::new("2023-11-15").is_err(), "date only");
        assert!(Datetime::new("2023-11-15T12:30:00").is_err(), "no timezone");
        assert!(
            Datetime::new("2023-11-15T12:30:00-00:00").is_err(),
            "-00:00 not allowed"
        );
        assert!(
            Datetime::new("0001-01-01T00:00:00Z").is_err(),
            "year starts with 000"
        );
    }

    #[test]
    fn normalize() {
        let result = normalize_datetime("2023-11-15T12:30:00Z").unwrap();
        assert_eq!(result, "2023-11-15T12:30:00.000Z");

        let result = normalize_datetime("2023-11-15T12:30:00.1Z").unwrap();
        assert_eq!(result, "2023-11-15T12:30:00.100Z");

        let result = normalize_datetime("2023-11-15T12:30:00.123456Z").unwrap();
        assert_eq!(result, "2023-11-15T12:30:00.123Z");
    }
}
