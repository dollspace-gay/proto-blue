//! Property-based tests for DAG-CBOR encoding/decoding.

use proptest::prelude::*;
use std::collections::BTreeMap;

use atproto_lex_data::LexValue;

// --- CBOR roundtrip property tests ---

proptest! {
    #[test]
    fn cbor_roundtrip_integers(n in proptest::num::i64::ANY) {
        let val = LexValue::Integer(n);
        let encoded = atproto_lex_cbor::encode(&val).unwrap();
        let decoded = atproto_lex_cbor::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, val);
    }

    #[test]
    fn cbor_roundtrip_strings(s in "[\\x00-\\x7F]{0,500}") {
        let val = LexValue::String(s.clone());
        let encoded = atproto_lex_cbor::encode(&val).unwrap();
        let decoded = atproto_lex_cbor::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, LexValue::String(s));
    }

    #[test]
    fn cbor_roundtrip_bytes(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        let val = LexValue::Bytes(data.clone());
        let encoded = atproto_lex_cbor::encode(&val).unwrap();
        let decoded = atproto_lex_cbor::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, LexValue::Bytes(data));
    }

    #[test]
    fn cbor_roundtrip_booleans(b in any::<bool>()) {
        let val = LexValue::Bool(b);
        let encoded = atproto_lex_cbor::encode(&val).unwrap();
        let decoded = atproto_lex_cbor::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, LexValue::Bool(b));
    }

    #[test]
    fn cbor_roundtrip_null(_dummy in Just(())) {
        let val = LexValue::Null;
        let encoded = atproto_lex_cbor::encode(&val).unwrap();
        let decoded = atproto_lex_cbor::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, LexValue::Null);
    }

    #[test]
    fn cbor_roundtrip_arrays(
        values in proptest::collection::vec(
            prop_oneof![
                Just(LexValue::Null),
                any::<bool>().prop_map(LexValue::Bool),
                any::<i64>().prop_map(LexValue::Integer),
                "[a-z]{0,20}".prop_map(|s| LexValue::String(s)),
            ],
            0..10
        )
    ) {
        let val = LexValue::Array(values.clone());
        let encoded = atproto_lex_cbor::encode(&val).unwrap();
        let decoded = atproto_lex_cbor::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, LexValue::Array(values));
    }

    #[test]
    fn cbor_roundtrip_maps(
        entries in proptest::collection::vec(
            ("[a-z]{1,10}", any::<i64>()),
            0..10
        )
    ) {
        let mut map = BTreeMap::new();
        for (k, v) in entries {
            map.insert(k, LexValue::Integer(v));
        }
        let val = LexValue::Map(map.clone());
        let encoded = atproto_lex_cbor::encode(&val).unwrap();
        let decoded = atproto_lex_cbor::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, LexValue::Map(map));
    }

    #[test]
    fn cbor_encoding_is_deterministic(
        entries in proptest::collection::vec(
            ("[a-z]{1,10}", any::<i64>()),
            0..10
        )
    ) {
        let mut map = BTreeMap::new();
        for (k, v) in entries {
            map.insert(k, LexValue::Integer(v));
        }
        let val = LexValue::Map(map);
        let encoded1 = atproto_lex_cbor::encode(&val).unwrap();
        let encoded2 = atproto_lex_cbor::encode(&val).unwrap();
        prop_assert_eq!(encoded1, encoded2, "DAG-CBOR encoding must be deterministic");
    }

    #[test]
    fn cbor_decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        // Should never panic, just return Ok or Err
        let _ = atproto_lex_cbor::decode(&data);
    }
}

// --- CID determinism ---

proptest! {
    #[test]
    fn cid_for_lex_is_deterministic(s in "[a-z]{0,100}") {
        let val = LexValue::String(s);
        let cid1 = atproto_lex_cbor::cid_for_lex(&val).unwrap();
        let cid2 = atproto_lex_cbor::cid_for_lex(&val).unwrap();
        prop_assert_eq!(cid1.to_string(), cid2.to_string());
    }

    #[test]
    fn different_values_produce_different_cids(
        a in "[a-z]{1,50}",
        b in "[a-z]{1,50}"
    ) {
        prop_assume!(a != b);
        let cid_a = atproto_lex_cbor::cid_for_lex(&LexValue::String(a)).unwrap();
        let cid_b = atproto_lex_cbor::cid_for_lex(&LexValue::String(b)).unwrap();
        prop_assert_ne!(cid_a.to_string(), cid_b.to_string());
    }
}
