//! Fuzz `AtUri` parsing.
//!
//! AT-URIs appear in record references and user input. The parser
//! takes arbitrary strings, so this surface must not panic or loop
//! on any input.
//!
//! Invariants:
//! - `AtUri::new(s)` must never panic.
//! - On success, `Display` must round-trip back to a value that
//!   re-parses equal to the original — otherwise we'd canonicalize
//!   an AT-URI to something that no longer refers to the same record.

#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_blue_syntax::AtUri;

fuzz_target!(|data: &[u8]| {
    // Only attempt to parse valid UTF-8; AT-URI isn't bytes.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(uri) = AtUri::new(s) {
        let formatted = uri.to_string();
        let reparsed = AtUri::new(&formatted).expect("re-parse of Display output");
        assert_eq!(
            uri, reparsed,
            "AtUri round-trip mismatch:\n  first={uri:?}\n  displayed={formatted:?}\n  reparsed={reparsed:?}"
        );
    }
});
