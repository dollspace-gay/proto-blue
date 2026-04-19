//! Fuzz `Tid` parsing + timestamp extraction.
//!
//! Invariants:
//! - `Tid::new` must never panic.
//! - `Tid::is_valid` must agree with `Tid::new`'s accept/reject.
//! - On accept, `timestamp_micros` must never panic and must always
//!   fit in the u64 it returns (no overflow).
//! - Round-trip: `Tid::new(tid.as_str()) == tid`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_blue_syntax::Tid;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let valid_fn = Tid::is_valid(s);
    let parsed = Tid::new(s);
    assert_eq!(
        valid_fn,
        parsed.is_ok(),
        "is_valid diverged from new() on {s:?}"
    );

    if let Ok(tid) = parsed {
        // Timestamp extraction must never panic.
        let _micros = tid.timestamp_micros();

        // Round-trip via string form.
        let reparsed = Tid::new(tid.as_str()).expect("re-parse of accepted TID");
        assert_eq!(tid, reparsed, "Tid round-trip mismatch");
    }
});
