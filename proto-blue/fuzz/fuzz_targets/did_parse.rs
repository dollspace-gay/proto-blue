//! Fuzz `Did` parsing.
//!
//! Invariants:
//! - `Did::new` must never panic.
//! - Accept-then-format must round-trip to an equal value.

#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_blue_syntax::Did;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(did) = Did::new(s) {
        let formatted = did.to_string();
        let reparsed = Did::new(&formatted).expect("re-parse of Display output");
        assert_eq!(did, reparsed, "Did round-trip mismatch");
    }
});
