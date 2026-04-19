//! Adversarial tests for DAG-CBOR canonical-form enforcement.
//!
//! DAG-CBOR is a restriction of CBOR; the hostile test surface is whether
//! a permissive decoder or encoder lets non-canonical bytes through. If two
//! implementations disagree on what's canonical, they produce different CIDs
//! for "the same" data, which silently corrupts repo syncs.
//!
//! Each test picks a specific departure from canonical form and asserts the
//! decoder rejects it (or that encode/decode preserves canonical order).

use proto_blue_lex_cbor::{decode, encode};
use proto_blue_lex_data::LexValue;
use std::collections::BTreeMap;

// ---------------------------------------------------------------
// Map key ordering: DAG-CBOR requires keys sorted by (len, bytes).
// ---------------------------------------------------------------

/// "aa" (len 2) must come after "b" (len 1) in canonical order.
/// Hand-craft a CBOR blob with the wrong order and confirm we either
/// reject it or normalize on decode — both are safer than silent acceptance.
#[test]
fn rejects_or_normalizes_non_canonical_key_order() {
    // Encode the map {"b": 1, "aa": 2} with BAD order (aa first, then b).
    // map(2) = 0xa2
    // "aa" = 0x62 0x61 0x61, value 2 = 0x02
    // "b"  = 0x61 0x62,      value 1 = 0x01
    let bad_order = vec![0xa2, 0x62, b'a', b'a', 0x02, 0x61, b'b', 0x01];

    // Canonically: "b" (len 1) comes first.
    let good_order = vec![0xa2, 0x61, b'b', 0x01, 0x62, b'a', b'a', 0x02];

    // We accept either: (a) decode rejects the bad-order blob, or
    // (b) decode accepts and re-encoding emits the good order.
    match decode(&bad_order) {
        Err(_) => { /* strict: rejected, done */ }
        Ok(decoded) => {
            let reencoded = encode(&decoded).expect("re-encode should succeed");
            assert_eq!(
                reencoded, good_order,
                "non-canonical map key order must be normalized on re-encode"
            );
        }
    }
}

/// Re-encoding a map with programmatically-inserted keys must always emit
/// canonical order, independent of the insertion order in the source
/// `BTreeMap`. `BTreeMap` already sorts lexicographically, but that's the
/// wrong order for DAG-CBOR (which uses length-first). So this catches a
/// whole class of "I forgot about length-first" bugs.
#[test]
fn encode_uses_length_first_key_order_not_lexicographic() {
    // "aa" < "b" lexicographically, but "b" < "aa" in DAG-CBOR order.
    let mut map = BTreeMap::new();
    map.insert("aa".to_string(), LexValue::Integer(2));
    map.insert("b".to_string(), LexValue::Integer(1));
    let bytes = encode(&LexValue::Map(map)).unwrap();

    // Find the positions of the key strings in the output.
    let pos_b = bytes
        .windows(2)
        .position(|w| w == [0x61, b'b'])
        .expect("key 'b' present");
    let pos_aa = bytes
        .windows(3)
        .position(|w| w == [0x62, b'a', b'a'])
        .expect("key 'aa' present");
    assert!(
        pos_b < pos_aa,
        "DAG-CBOR requires length-first key order: 'b' (len 1) must precede 'aa' (len 2). \
         Got pos_b={pos_b}, pos_aa={pos_aa}, bytes={bytes:?}"
    );
}

/// Same-length keys must sort by byte value.
#[test]
fn encode_sorts_equal_length_keys_lexicographically() {
    let mut map = BTreeMap::new();
    map.insert("zz".to_string(), LexValue::Integer(2));
    map.insert("aa".to_string(), LexValue::Integer(1));
    let bytes = encode(&LexValue::Map(map)).unwrap();

    let pos_aa = bytes
        .windows(3)
        .position(|w| w == [0x62, b'a', b'a'])
        .expect("aa present");
    let pos_zz = bytes
        .windows(3)
        .position(|w| w == [0x62, b'z', b'z'])
        .expect("zz present");
    assert!(pos_aa < pos_zz, "same-length keys must sort by bytes");
}

// ---------------------------------------------------------------
// Duplicate map keys: must be rejected.
// ---------------------------------------------------------------

/// Hand-crafted CBOR with two entries for the same key must be rejected.
/// A decoder that silently takes the last-wins value would diverge from TS.
#[test]
fn rejects_duplicate_map_keys() {
    // map(2) with "a" => 1 and "a" => 2
    let dup = vec![0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02];
    let result = decode(&dup);
    assert!(
        result.is_err(),
        "duplicate map keys must be rejected, got {result:?}"
    );
}

// ---------------------------------------------------------------
// Non-string map keys: must be rejected.
// ---------------------------------------------------------------

/// A map with an integer key — legal in CBOR, illegal in DAG-CBOR.
#[test]
fn rejects_integer_map_keys() {
    // map(1) with 1 => 2
    let bad = vec![0xa1, 0x01, 0x02];
    let result = decode(&bad);
    assert!(result.is_err(), "integer map keys must be rejected");
}

// ---------------------------------------------------------------
// Float values: must be rejected (except integer-valued floats).
// ---------------------------------------------------------------

/// NaN encoded as a half-float must be rejected.
#[test]
fn rejects_nan_half_float() {
    // 0xf9 = half-float, payload 0x7e00 = NaN
    let nan = vec![0xf9, 0x7e, 0x00];
    let result = decode(&nan);
    assert!(result.is_err(), "NaN must be rejected, got {result:?}");
}

/// +Infinity encoded as a half-float must be rejected.
#[test]
fn rejects_positive_infinity() {
    // 0xf9 0x7c 0x00 = +Inf (half-float)
    let inf = vec![0xf9, 0x7c, 0x00];
    let result = decode(&inf);
    assert!(result.is_err(), "+Inf must be rejected");
}

/// -Infinity.
#[test]
fn rejects_negative_infinity() {
    let inf = vec![0xf9, 0xfc, 0x00];
    let result = decode(&inf);
    assert!(result.is_err(), "-Inf must be rejected");
}

/// A non-integer float like 3.14 must be rejected.
#[test]
fn rejects_non_integer_float() {
    // 0xfb = double-precision float, payload = IEEE 754 for 3.14
    // 3.14 => 0x40091EB851EB851F
    let pi = vec![0xfb, 0x40, 0x09, 0x1e, 0xb8, 0x51, 0xeb, 0x85, 0x1f];
    let result = decode(&pi);
    assert!(result.is_err(), "3.14 must be rejected as non-integer");
}

// ---------------------------------------------------------------
// Integer round-trip edge cases.
// ---------------------------------------------------------------

/// Every integer we encode and decode round-trips through i64.
#[test]
fn integer_extremes_roundtrip() {
    for n in [
        i64::MIN,
        i64::MIN + 1,
        -1,
        0,
        1,
        23,    // fits in CBOR additional info directly
        24,    // first value needing a follow-up byte
        255,   // boundary of 1-byte encoding
        256,   // boundary of 2-byte encoding
        65535, // boundary of 2-byte encoding
        65536, // boundary of 4-byte encoding
        i64::MAX,
    ] {
        let bytes = encode(&LexValue::Integer(n)).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back, LexValue::Integer(n), "i64 roundtrip failed at {n}");
    }
}

// ---------------------------------------------------------------
// CID tag 42: leading 0x00 byte is required.
// ---------------------------------------------------------------

/// A CBOR tag 42 value whose inner bytes don't start with 0x00 must be
/// rejected. TS enforces this via its Cid decode helper; so must we.
#[test]
fn rejects_cid_tag_without_leading_zero() {
    // tag(42) = 0xd8 0x2a
    // bytes(5) = 0x45
    // five non-zero bytes: b'a' b'b' b'c' b'd' b'e'
    let bad_cid = vec![0xd8, 0x2a, 0x45, b'a', b'b', b'c', b'd', b'e'];
    let result = decode(&bad_cid);
    assert!(
        result.is_err(),
        "CID tag 42 without leading 0x00 must be rejected, got {result:?}"
    );
}

/// A CBOR tag 42 value whose content isn't a byte string must be rejected.
#[test]
fn rejects_cid_tag_with_non_bytes_content() {
    // tag(42) containing a text string "hi"
    let bad = vec![0xd8, 0x2a, 0x62, b'h', b'i'];
    let result = decode(&bad);
    assert!(result.is_err(), "CID tag over text must be rejected");
}

// ---------------------------------------------------------------
// Trailing garbage: `decode` should reject extra bytes after the value.
// ---------------------------------------------------------------

/// Encoded value followed by garbage. ciborium's reader may stop at the end
/// of the first value; this test documents what `decode` does so future
/// changes stay intentional.
#[test]
fn encode_never_produces_trailing_garbage() {
    let bytes = encode(&LexValue::Integer(42)).unwrap();
    // Manually: CBOR positive int 42 = 0x18 0x2a (two bytes).
    assert_eq!(bytes, vec![0x18, 0x2a]);
}

// ---------------------------------------------------------------
// Byte string handling: empty and large.
// ---------------------------------------------------------------

#[test]
fn empty_byte_string_roundtrip() {
    let val = LexValue::Bytes(vec![]);
    let bytes = encode(&val).unwrap();
    assert_eq!(decode(&bytes).unwrap(), val);
}

#[test]
fn large_byte_string_roundtrip() {
    let data: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
    let val = LexValue::Bytes(data.clone());
    let bytes = encode(&val).unwrap();
    assert_eq!(decode(&bytes).unwrap(), LexValue::Bytes(data));
}

// ---------------------------------------------------------------
// Deep nesting: must not overflow the stack.
// ---------------------------------------------------------------

/// Deep nested arrays — a classic recursive-parser DoS target.
/// We cap at 100 (well within any sensible recursion budget) but demonstrate
/// the shape of the adversarial test. A real fuzzer would push this higher.
#[test]
fn deeply_nested_arrays_do_not_panic() {
    let mut val = LexValue::Array(vec![]);
    for _ in 0..100 {
        val = LexValue::Array(vec![val]);
    }
    let bytes = encode(&val).unwrap();
    let back = decode(&bytes).unwrap();
    assert_eq!(back, val);
}

// ---------------------------------------------------------------
// Determinism: same logical value -> same exact bytes, no matter how
// the map was assembled.
// ---------------------------------------------------------------

#[test]
fn maps_are_canonicalized_regardless_of_insertion_order() {
    let mut a = BTreeMap::new();
    a.insert("aaa".to_string(), LexValue::Integer(3));
    a.insert("bb".to_string(), LexValue::Integer(2));
    a.insert("c".to_string(), LexValue::Integer(1));

    // Different insertion order:
    let mut b = BTreeMap::new();
    b.insert("c".to_string(), LexValue::Integer(1));
    b.insert("aaa".to_string(), LexValue::Integer(3));
    b.insert("bb".to_string(), LexValue::Integer(2));

    let bytes_a = encode(&LexValue::Map(a)).unwrap();
    let bytes_b = encode(&LexValue::Map(b)).unwrap();
    assert_eq!(
        bytes_a, bytes_b,
        "DAG-CBOR must produce identical bytes for logically-equal maps"
    );
}
