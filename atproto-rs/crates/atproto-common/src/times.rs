//! Time constants and utilities.

use std::time::Duration;

/// One second in milliseconds.
pub const SECOND: u64 = 1_000;

/// One minute in milliseconds.
pub const MINUTE: u64 = 60 * SECOND;

/// One hour in milliseconds.
pub const HOUR: u64 = 60 * MINUTE;

/// One day in milliseconds.
pub const DAY: u64 = 24 * HOUR;

/// Check if a timestamp (in milliseconds) is less than `range_ms` ago.
pub fn less_than_ago_ms(time_ms: u64, range_ms: u64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    now.saturating_sub(time_ms) < range_ms
}

/// Create a Duration from milliseconds.
pub fn duration_ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_constants() {
        assert_eq!(SECOND, 1_000);
        assert_eq!(MINUTE, 60_000);
        assert_eq!(HOUR, 3_600_000);
        assert_eq!(DAY, 86_400_000);
    }

    #[test]
    fn recent_timestamp_is_less_than_ago() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(less_than_ago_ms(now, MINUTE));
        assert!(less_than_ago_ms(now - 500, SECOND));
    }

    #[test]
    fn old_timestamp_is_not_less_than_ago() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(!less_than_ago_ms(now - 2000, SECOND));
    }
}
