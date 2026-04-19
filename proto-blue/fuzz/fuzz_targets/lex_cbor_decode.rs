//! Fuzz the strict DAG-CBOR decoder with arbitrary bytes.
//!
//! Invariants:
//! - `decode` / `decode_all` must never panic on any byte sequence.
//! - On decode success, re-encoding must produce identical bytes
//!   (canonical-form round-trip). This is the core contract of
//!   DAG-CBOR: there is exactly one valid encoding per value.

#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_blue_lex_cbor::{decode, decode_all, encode};

fuzz_target!(|data: &[u8]| {
    // `decode` must not panic, period.
    if let Ok(value) = decode(data) {
        // Round-trip: a successfully-decoded value must re-encode
        // byte-identically. Catches non-canonical encodings that
        // slipped past the strict check.
        let re_encoded = encode(&value).expect("encode of decoded value");
        assert_eq!(
            data.to_vec(),
            re_encoded,
            "canonical-form violation: decode accepted non-canonical input",
        );
    }

    // Same contract on the streaming `decode_all` entry point.
    if let Ok(values) = decode_all(data) {
        let mut re_encoded = Vec::with_capacity(data.len());
        for v in &values {
            let bytes = encode(v).expect("encode of decoded value");
            re_encoded.extend_from_slice(&bytes);
        }
        assert_eq!(
            data.to_vec(),
            re_encoded,
            "decode_all non-canonical round-trip",
        );
    }
});
