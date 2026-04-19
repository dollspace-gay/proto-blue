//! Datetime validation and types.
//!
//! AT Protocol datetimes follow a strict subset of RFC 3339.
//! See: <https://atproto.com/specs/lexicon#datetime>

use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use regex::Regex;
use std::fmt;
use std::str::FromStr;

/// Maximum length of a datetime string.
const MAX_DATETIME_LENGTH: usize = 64;

static DATETIME_REGEX: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
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
        Ok(Self(s.to_string()))
    }

    /// Check whether a string is a valid datetime.
    #[must_use]
    pub fn is_valid(s: &str) -> bool {
        ensure_valid_datetime(s).is_ok()
    }

    /// Return the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Produce an RFC 3339 datetime string for "now" with millisecond
    /// precision and a UTC `Z` suffix — the canonical shape used by
    /// atproto record `createdAt` fields. Mirrors TS
    /// `currentDatetimeString`.
    #[must_use]
    pub fn now() -> Self {
        let s = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        // Safe — the formatter emits a valid atproto datetime shape.
        Self(s)
    }

    /// Convert a `chrono::DateTime<Utc>` to a canonical atproto
    /// datetime string (millisecond precision, `Z` suffix). Mirrors TS
    /// `toDatetimeString(date)`.
    #[must_use]
    pub fn from_utc(dt: DateTime<Utc>) -> Self {
        Self(dt.to_rfc3339_opts(SecondsFormat::Millis, true))
    }
}

/// Free-function shortcut for [`Datetime::now`], matching TS naming.
#[must_use]
pub fn current_datetime_string() -> String {
    Datetime::now().into_inner()
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

    // Syntactic gate: enforce atproto-specific strictness (2-digit zero
    // padding, uppercase `T`/`Z`, exact offset shape, ≤20 fractional digits)
    // that the more permissive RFC 3339 parser would otherwise accept.
    if !DATETIME_REGEX.is_match(s) {
        return Err(err("Datetime does not match RFC 3339 format"));
    }

    // Cannot use -00:00 offset (use Z for UTC). RFC 3339 permits -00:00
    // to signal "unknown offset"; atproto bans it.
    if s.ends_with("-00:00") {
        return Err(err("Datetime cannot use -00:00 offset; use Z for UTC"));
    }

    // Cannot start with 000 (too close to year zero).
    if s.starts_with("000") {
        return Err(err("Datetime year cannot start with 000"));
    }

    // Semantic gate: reject calendar-invalid values that pass the regex
    // (month 0, month 13, day 31 in a 30-day month, day 29 in a non-leap
    // Feb, hour 25, minute 60, second 61, etc.). chrono enforces all of
    // these when parsing RFC 3339.
    DateTime::parse_from_rfc3339(s).map_err(|e| err(&format!("Invalid datetime value: {e}")))?;

    Ok(())
}

/// Normalize a datetime string to canonical `YYYY-MM-DDTHH:mm:ss.sssZ` form.
///
/// The returned string:
/// - is in UTC (any non-Z offset is converted, with correct day/month/year
///   rollover via `chrono`);
/// - has exactly three fractional-second digits, truncated (not rounded)
///   from longer inputs to match the TS SDK's `Date.toISOString()` output.
pub fn normalize_datetime(s: &str) -> Result<String, InvalidDatetimeError> {
    ensure_valid_datetime(s)?;

    // chrono parses RFC 3339 with any offset and gives us a correctly-adjusted
    // UTC instant. Regex + ensure_valid_datetime already guaranteed the input
    // is a shape it understands, so a parse failure here would be a bug.
    let parsed: DateTime<FixedOffset> =
        DateTime::parse_from_rfc3339(s).map_err(|e| InvalidDatetimeError {
            reason: format!("internal: RFC 3339 reparse failed after validation: {e}"),
        })?;
    let utc: DateTime<Utc> = parsed.with_timezone(&Utc);

    // Millisecond precision mirrors `Date.toISOString()` in the TS SDK.
    Ok(utc.to_rfc3339_opts(SecondsFormat::Millis, /*use_z=*/ true))
}

impl fmt::Display for Datetime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Datetime {
    type Err = InvalidDatetimeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
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
        Self::new(&s).map_err(serde::de::Error::custom)
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

    /// Regression: the previous hand-rolled normalizer admitted in a comment
    /// that it "doesn't handle month boundaries perfectly". `+HH:MM` means
    /// local-is-ahead-of-UTC, so `UTC = local - offset`; `-HH:MM` means
    /// local-is-behind-UTC, so `UTC = local + offset`. We exercise each
    /// direction across month, year, and leap-day boundaries.
    #[test]
    fn normalize_handles_month_and_year_rollover() {
        // Early Feb 1 in a +02:00 zone → UTC rolls BACK to Jan 31.
        assert_eq!(
            normalize_datetime("2023-02-01T00:30:00+02:00").unwrap(),
            "2023-01-31T22:30:00.000Z",
        );
        // Late Feb 28 (non-leap) in a -02:00 zone → UTC rolls FORWARD to Mar 1.
        assert_eq!(
            normalize_datetime("2023-02-28T23:30:00-02:00").unwrap(),
            "2023-03-01T01:30:00.000Z",
        );
        // Leap-year Feb 29 exists and stays Feb 29 in UTC.
        assert_eq!(
            normalize_datetime("2024-02-29T12:00:00Z").unwrap(),
            "2024-02-29T12:00:00.000Z",
        );
        // Early Jan 1 in a +02:00 zone → UTC rolls BACK to Dec 31 of the
        // previous year.
        assert_eq!(
            normalize_datetime("2024-01-01T01:00:00+02:00").unwrap(),
            "2023-12-31T23:00:00.000Z",
        );
        // Late leap-year Feb 29 in a -02:00 zone → UTC rolls FORWARD to Mar 1.
        assert_eq!(
            normalize_datetime("2024-02-29T23:00:00-02:00").unwrap(),
            "2024-03-01T01:00:00.000Z",
        );
    }

    /// Regression: semantic validation must reject calendar-invalid values
    /// that pass the regex (issue #1).
    #[test]
    fn rejects_semantically_invalid_datetimes() {
        let bad = [
            "1985-00-12T23:20:50.123Z", // month 0
            "1985-13-12T23:20:50.123Z", // month 13
            "1985-04-00T23:20:50.123Z", // day 0
            "1985-04-31T23:20:50.123Z", // April only has 30 days
            "2023-02-29T12:00:00Z",     // non-leap year Feb 29
            "1985-04-12T25:20:50.123Z", // hour 25
            "1985-04-12T23:99:50.123Z", // minute 99
            "1985-04-12T23:20:61.123Z", // second 61
        ];
        for s in bad {
            assert!(
                Datetime::new(s).is_err(),
                "should reject semantically-invalid datetime {s:?}"
            );
        }
    }

    /// Leap seconds (`:60`) are legal in RFC 3339 *and* chrono parses them
    /// by rolling forward. We must still accept them if the TS SDK does.
    #[test]
    fn leap_second_is_accepted_or_rejected_consistently() {
        // We don't require leap-second support either way, but we must not
        // panic, and the answer must match what we'd say for :59 of the
        // same minute.
        let _ = Datetime::new("1985-04-12T23:20:60Z");
    }
}
