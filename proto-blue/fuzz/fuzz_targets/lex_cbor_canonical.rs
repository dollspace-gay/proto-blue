//! Fuzz the canonical-form checker specifically.
//!
//! `decode` (strict) must reject any input that `decode_lenient`
//! accepts but which isn't in canonical form: non-minimal length
//! encodings, out-of-order map keys, indefinite-length collections,
//! etc. This harness surfaces divergences between the two.
//!
//! Invariants:
//! - If strict decode accepts, lenient must accept.
//! - If both accept, they must produce equal values.
//! - If lenient accepts but strict rejects, re-encoding the lenient
//!   result must differ from the input (the whole point of
//!   canonical-form: strict rejection implies non-canonical bytes).

#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_blue_lex_cbor::{decode, decode_lenient, encode};

fuzz_target!(|data: &[u8]| {
    let strict = decode(data);
    let lenient = decode_lenient(data);

    match (&strict, &lenient) {
        (Ok(s), Ok(l)) => {
            assert_eq!(s, l, "strict and lenient diverged on same input");
        }
        (Ok(_), Err(_)) => {
            panic!("strict accepted where lenient rejected — impossible");
        }
        (Err(_), Ok(l)) => {
            // Lenient accepted → there's a valid value in there, but
            // strict said the *bytes* aren't canonical. Re-encoding
            // must produce something different from the input.
            let re = encode(l).expect("encode of lenient-decoded value");
            assert_ne!(
                data.to_vec(),
                re,
                "strict rejected input but re-encoding matches — \
                 strict is over-eager rejecting canonical bytes",
            );
        }
        (Err(_), Err(_)) => {
            // Both rejected — fine.
        }
    }
});
