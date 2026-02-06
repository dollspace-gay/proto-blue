//! Bidirectional conversion between JSON and LexValue.
//!
//! In JSON representation:
//! - CIDs are encoded as `{"$link": "bafy..."}`
//! - Byte arrays are encoded as `{"$bytes": "<base64>"}`
//! - Blob refs are `{"$type": "blob", "ref": {"$link": "..."}, "mimeType": "...", "size": N}`

use std::collections::BTreeMap;

use atproto_lex_data::{Cid, LexValue};
use base64::Engine as _;
use serde_json::Value as JsonValue;

use crate::error::JsonError;

/// Base64 engine: standard alphabet, no padding, lenient decode.
const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// Serialize a LexValue to a JSON string.
pub fn lex_stringify(value: &LexValue) -> String {
    let json = lex_to_json(value);
    serde_json::to_string(&json).expect("LexValue should always serialize to valid JSON")
}

/// Parse a JSON string to a LexValue.
pub fn lex_parse(input: &str) -> Result<LexValue, JsonError> {
    let json: JsonValue = serde_json::from_str(input)?;
    Ok(json_to_lex(&json))
}

/// Convert a JSON value to a LexValue.
///
/// Recognizes special object patterns:
/// - `{"$link": "..."}` (exactly one key) → `LexValue::Cid`
/// - `{"$bytes": "..."}` (exactly one key) → `LexValue::Bytes`
/// - Objects with `$type`, `$link`, or `$bytes` alongside other keys are kept as maps
pub fn json_to_lex(json: &JsonValue) -> LexValue {
    match json {
        JsonValue::Null => LexValue::Null,
        JsonValue::Bool(b) => LexValue::Bool(*b),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                LexValue::Integer(i)
            } else if let Some(f) = n.as_f64() {
                // Try to convert float to integer if it's exact
                if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
                    LexValue::Integer(f as i64)
                } else {
                    // AT Data Model doesn't support floats, but we preserve as integer
                    // truncation for compatibility
                    LexValue::Integer(f as i64)
                }
            } else {
                LexValue::Null
            }
        }
        JsonValue::String(s) => LexValue::String(s.clone()),
        JsonValue::Array(arr) => LexValue::Array(arr.iter().map(json_to_lex).collect()),
        JsonValue::Object(obj) => {
            // Check for $link (CID) — must have exactly one key
            if obj.len() == 1 {
                if let Some(JsonValue::String(link)) = obj.get("$link") {
                    if let Ok(cid) = link.parse::<Cid>() {
                        return LexValue::Cid(cid);
                    }
                }
                if let Some(JsonValue::String(b64)) = obj.get("$bytes") {
                    if let Ok(bytes) = BASE64_ENGINE.decode(b64) {
                        return LexValue::Bytes(bytes);
                    }
                }
            }

            // Regular object — convert recursively
            let mut map = BTreeMap::new();
            for (key, value) in obj {
                if key == "__proto__" {
                    continue; // Prevent prototype pollution
                }
                map.insert(key.clone(), json_to_lex(value));
            }
            LexValue::Map(map)
        }
    }
}

/// Convert a LexValue to a JSON value.
///
/// CIDs become `{"$link": "..."}`, byte arrays become `{"$bytes": "..."}`.
pub fn lex_to_json(value: &LexValue) -> JsonValue {
    match value {
        LexValue::Null => JsonValue::Null,
        LexValue::Bool(b) => JsonValue::Bool(*b),
        LexValue::Integer(n) => JsonValue::Number((*n).into()),
        LexValue::String(s) => JsonValue::String(s.clone()),
        LexValue::Bytes(b) => {
            let encoded = BASE64_ENGINE.encode(b);
            let mut obj = serde_json::Map::new();
            obj.insert("$bytes".to_string(), JsonValue::String(encoded));
            JsonValue::Object(obj)
        }
        LexValue::Cid(cid) => {
            let mut obj = serde_json::Map::new();
            obj.insert("$link".to_string(), JsonValue::String(cid.to_string()));
            JsonValue::Object(obj)
        }
        LexValue::Array(arr) => JsonValue::Array(arr.iter().map(lex_to_json).collect()),
        LexValue::Map(map) => {
            let mut obj = serde_json::Map::new();
            for (key, val) in map {
                obj.insert(key.clone(), lex_to_json(val));
            }
            JsonValue::Object(obj)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_null() {
        let lex = LexValue::Null;
        let json = lex_to_json(&lex);
        assert_eq!(json, JsonValue::Null);
        assert_eq!(json_to_lex(&json), lex);
    }

    #[test]
    fn roundtrip_bool() {
        for b in [true, false] {
            let lex = LexValue::Bool(b);
            let json = lex_to_json(&lex);
            assert_eq!(json, JsonValue::Bool(b));
            assert_eq!(json_to_lex(&json), lex);
        }
    }

    #[test]
    fn roundtrip_integer() {
        for n in [0i64, 1, -1, 42, 123, -999] {
            let lex = LexValue::Integer(n);
            let json = lex_to_json(&lex);
            assert_eq!(json_to_lex(&json), lex);
        }
    }

    #[test]
    fn roundtrip_string() {
        let strings = ["", "hello", "a~öñ©⽘☎𓋓😀", "with spaces"];
        for s in strings {
            let lex = LexValue::String(s.to_string());
            let json = lex_to_json(&lex);
            assert_eq!(json, JsonValue::String(s.to_string()));
            assert_eq!(json_to_lex(&json), lex);
        }
    }

    #[test]
    fn cid_link_encoding() {
        let cid = Cid::for_cbor(b"test data");
        let lex = LexValue::Cid(cid.clone());

        let json = lex_to_json(&lex);
        match &json {
            JsonValue::Object(obj) => {
                assert_eq!(obj.len(), 1);
                assert!(obj.contains_key("$link"));
                assert_eq!(obj["$link"], JsonValue::String(cid.to_string()));
            }
            _ => panic!("CID should encode as object"),
        }

        // Roundtrip
        let decoded = json_to_lex(&json);
        assert_eq!(decoded, lex);
    }

    #[test]
    fn bytes_encoding() {
        let data = vec![156, 81, 17, 142, 242, 203, 139, 15];
        let lex = LexValue::Bytes(data.clone());

        let json = lex_to_json(&lex);
        match &json {
            JsonValue::Object(obj) => {
                assert_eq!(obj.len(), 1);
                assert!(obj.contains_key("$bytes"));
                // Verify base64 encoding (no padding)
                let b64 = obj["$bytes"].as_str().unwrap();
                assert!(!b64.contains('='), "Should not have padding");
                let decoded_bytes = BASE64_ENGINE.decode(b64).unwrap();
                assert_eq!(decoded_bytes, data);
            }
            _ => panic!("Bytes should encode as object"),
        }

        // Roundtrip
        let decoded = json_to_lex(&json);
        assert_eq!(decoded, lex);
    }

    #[test]
    fn link_with_extra_keys_stays_as_map() {
        // {"$link": "bafy...", "another": "bad value"} should NOT be parsed as CID
        let json_str = r#"{"$link": "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a", "another": "bad value"}"#;
        let json: JsonValue = serde_json::from_str(json_str).unwrap();
        let lex = json_to_lex(&json);

        match &lex {
            LexValue::Map(map) => {
                assert_eq!(map.len(), 2);
                assert!(map.contains_key("$link"));
                assert!(map.contains_key("another"));
            }
            _ => panic!("Should be a map, not a CID"),
        }
    }

    #[test]
    fn bytes_with_extra_keys_stays_as_map() {
        let json_str =
            r#"{"$bytes": "nFERjvLLiw9qm45JrqH9QTzyC2Lu1Xb4ne6+sBrCzI0", "another": "bad value"}"#;
        let json: JsonValue = serde_json::from_str(json_str).unwrap();
        let lex = json_to_lex(&json);

        match &lex {
            LexValue::Map(map) => {
                assert_eq!(map.len(), 2);
                assert!(map.contains_key("$bytes"));
                assert!(map.contains_key("another"));
            }
            _ => panic!("Should be a map, not bytes"),
        }
    }

    #[test]
    fn lex_stringify_roundtrip() {
        let cid = Cid::for_cbor(b"test");
        let mut map = BTreeMap::new();
        map.insert("text".to_string(), LexValue::String("hello".into()));
        map.insert("cid".to_string(), LexValue::Cid(cid));
        map.insert("data".to_string(), LexValue::Bytes(vec![1, 2, 3]));
        let val = LexValue::Map(map);

        let json_str = lex_stringify(&val);
        let parsed = lex_parse(&json_str).unwrap();
        assert_eq!(val, parsed);
    }

    #[test]
    fn nested_cids_and_bytes() {
        let cid: Cid = "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"
            .parse()
            .unwrap();

        let val = LexValue::Array(vec![
            LexValue::Cid(cid),
            LexValue::Bytes(vec![10, 20, 30]),
            LexValue::String("plain".into()),
        ]);

        let json_str = lex_stringify(&val);
        let parsed = lex_parse(&json_str).unwrap();
        assert_eq!(val, parsed);
    }

    #[test]
    fn blob_ref_preserved_as_map() {
        // Blob refs have $type, ref, mimeType, size — not a special single-key pattern
        let json_str = r#"{"$type": "blob", "ref": {"$link": "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity"}, "mimeType": "image/jpeg", "size": 10000}"#;
        let json: JsonValue = serde_json::from_str(json_str).unwrap();
        let lex = json_to_lex(&json);

        match &lex {
            LexValue::Map(map) => {
                assert_eq!(map.get("$type").unwrap().as_str(), Some("blob"));
                // The ref field should be a CID (parsed from the $link pattern)
                assert!(map.get("ref").unwrap().as_cid().is_some());
                assert_eq!(map.get("mimeType").unwrap().as_str(), Some("image/jpeg"));
                assert_eq!(map.get("size").unwrap().as_integer(), Some(10000));
            }
            _ => panic!("Blob ref should be a map"),
        }
    }

    #[test]
    fn empty_structures() {
        let empty_arr = LexValue::Array(vec![]);
        let json = lex_to_json(&empty_arr);
        assert_eq!(json, JsonValue::Array(vec![]));
        assert_eq!(json_to_lex(&json), empty_arr);

        let empty_map = LexValue::Map(BTreeMap::new());
        let json = lex_to_json(&empty_map);
        assert_eq!(json, JsonValue::Object(serde_json::Map::new()));
        assert_eq!(json_to_lex(&json), empty_map);
    }

    #[test]
    fn ipld_test_vector_roundtrip() {
        // From the TS test suite "ipld" vector
        let json_str = r#"{"a":{"$link":"bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"},"b":{"$bytes":"nFERjvLLiw9qm45JrqH9QTzyC2Lu1Xb4ne6+sBrCzI0"},"c":{"$type":"blob","ref":{"$link":"bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity"},"mimeType":"image/jpeg","size":10000}}"#;

        let lex = lex_parse(json_str).unwrap();
        let back = lex_stringify(&lex);
        let lex2 = lex_parse(&back).unwrap();
        assert_eq!(lex, lex2);

        // Verify specific types
        let map = lex.as_map().unwrap();
        assert!(map["a"].as_cid().is_some(), "a should be a CID");
        assert!(map["b"].as_bytes().is_some(), "b should be bytes");
        assert!(map["c"].as_map().is_some(), "c should be a map (blob ref)");
    }

    #[test]
    fn poorly_formatted_not_parsed_as_special() {
        // CID string values (not in $link wrapper) stay as strings
        let json_str = r#"{"a": "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"}"#;
        let lex = lex_parse(json_str).unwrap();
        let map = lex.as_map().unwrap();
        assert!(map["a"].as_str().is_some(), "Should be a string, not a CID");
    }
}
