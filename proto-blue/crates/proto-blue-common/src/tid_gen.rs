//! TID (Timestamp ID) generator.
//!
//! Generates monotonically increasing TIDs with microsecond-level precision.
//! Uses a counter to differentiate multiple TIDs generated within the same
//! millisecond, and a random clock ID to avoid collisions across machines.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use proto_blue_syntax::Tid;

/// Base32-sortable character set used for TID encoding.
const S32_CHAR: &[u8] = b"234567abcdefghijklmnopqrstuvwxyz";

/// TID generator state.
struct TidGenState {
    last_timestamp: u64,
    timestamp_count: u64,
    clock_id: u32,
}

static TID_STATE: Mutex<Option<TidGenState>> = Mutex::new(None);

/// Generate the next TID, monotonically increasing.
///
/// If `prev` is provided, the returned TID is guaranteed to be newer.
/// Uses millisecond timestamps multiplied by 1000 plus a counter for
/// sub-millisecond ordering. A random clock ID (0-31) is assigned on
/// first use and reused for all subsequent TIDs from this process.
pub fn next_tid(prev: Option<&Tid>) -> Tid {
    let mut guard = TID_STATE.lock().unwrap();
    let state = guard.get_or_insert_with(|| TidGenState {
        last_timestamp: 0,
        timestamp_count: 0,
        clock_id: rand::random::<u32>() % 32,
    });

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Take max of current time and last timestamp to handle clock drift
    let time = now_ms.max(state.last_timestamp);
    if time == state.last_timestamp {
        state.timestamp_count += 1;
    } else {
        state.timestamp_count = 0;
    }
    state.last_timestamp = time;

    let timestamp = time * 1000 + state.timestamp_count;
    let tid = tid_from_time(timestamp, state.clock_id);

    if let Some(prev) = prev {
        if tid.as_str() <= prev.as_str() {
            // Ensure monotonically increasing by bumping past prev
            let prev_ts = s32_decode(&prev.as_str()[..11]);
            return tid_from_time(prev_ts + 1, state.clock_id);
        }
    }

    tid
}

/// Generate a TID string from a timestamp and clock ID.
fn tid_from_time(timestamp: u64, clock_id: u32) -> Tid {
    let ts_str = s32_encode(timestamp);
    let cid_str = s32_encode(clock_id as u64);
    // Pad timestamp to 11 chars and clock ID to 2 chars with '2' (the '0' of s32)
    let ts_padded = format!("{:2>11}", ts_str);
    let cid_padded = if cid_str.is_empty() {
        "22".to_string()
    } else if cid_str.len() == 1 {
        format!("2{cid_str}")
    } else {
        cid_str
    };
    let s = format!("{ts_padded}{cid_padded}");
    Tid::new(&s).expect("Generated TID should be valid")
}

/// Encode a number to base32-sortable string.
fn s32_encode(mut i: u64) -> String {
    if i == 0 {
        return String::new();
    }
    let mut s = Vec::new();
    while i > 0 {
        let c = (i % 32) as usize;
        i /= 32;
        s.push(S32_CHAR[c]);
    }
    s.reverse();
    String::from_utf8(s).unwrap()
}

/// Decode a base32-sortable string to a number.
fn s32_decode(s: &str) -> u64 {
    let mut i: u64 = 0;
    for c in s.bytes() {
        let idx = S32_CHAR.iter().position(|&b| b == c).unwrap_or(0);
        i = i * 32 + idx as u64;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_tid_is_valid() {
        let tid = next_tid(None);
        assert_eq!(tid.as_str().len(), 13);
    }

    #[test]
    fn next_tid_is_monotonic() {
        let t1 = next_tid(None);
        let t2 = next_tid(None);
        let t3 = next_tid(None);
        assert!(t2.as_str() > t1.as_str(), "t2 should be newer than t1");
        assert!(t3.as_str() > t2.as_str(), "t3 should be newer than t2");
    }

    #[test]
    fn next_tid_newer_than_prev() {
        let prev = Tid::new("3jqfcqzm3fo2j").unwrap();
        let tid = next_tid(Some(&prev));
        assert!(
            tid.as_str() > prev.as_str(),
            "Generated TID should be newer than prev"
        );
    }

    #[test]
    fn s32_encode_decode_roundtrip() {
        for val in [0u64, 1, 31, 32, 1000, 1_000_000, u64::MAX / 2] {
            if val == 0 {
                // 0 encodes to empty string, which decodes to 0
                assert_eq!(s32_decode(&s32_encode(val)), 0);
            } else {
                assert_eq!(s32_decode(&s32_encode(val)), val);
            }
        }
    }

    #[test]
    fn tid_from_time_produces_valid_tid() {
        let tid = tid_from_time(1_700_000_000_000, 5);
        assert_eq!(tid.as_str().len(), 13);
    }
}
