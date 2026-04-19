//! Fuzz `Nsid` parsing.
//!
//! Invariants:
//! - `Nsid::new` must never panic.
//! - Accept-then-format must round-trip to an equal value.

#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_blue_syntax::Nsid;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(nsid) = Nsid::new(s) {
        let formatted = nsid.to_string();
        let reparsed = Nsid::new(&formatted).expect("re-parse of Display output");
        assert_eq!(nsid, reparsed, "Nsid round-trip mismatch");
    }
});
