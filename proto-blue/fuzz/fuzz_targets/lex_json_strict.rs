//! Fuzz the JSON-to-LexValue strict parser.
//!
//! Invariants:
//! - `lex_parse_json_bytes` must never panic.
//! - On success, `lex_stringify` → `lex_parse_json_bytes` must
//!   round-trip to an equal value. JSON isn't canonical the way
//!   DAG-CBOR is (key order / whitespace vary), but the resulting
//!   `LexValue` tree must be structurally identical.

#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_blue_lex_json::{lex_parse_json_bytes, lex_stringify};

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = lex_parse_json_bytes(data) {
        // Round-trip value → string → value must preserve semantics.
        let s = lex_stringify(&value);
        let reparsed =
            lex_parse_json_bytes(s.as_bytes()).expect("reparse of self-produced JSON must succeed");
        assert_eq!(
            value, reparsed,
            "JSON round-trip altered value: first={value:?} reparsed={reparsed:?}"
        );
    }
});
