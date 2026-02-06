//! DAG-CBOR encoding and decoding for AT Protocol data.
//!
//! Implements strict DAG-CBOR rules:
//! - No floats (integers only in the AT Data Model)
//! - No NaN or Infinity
//! - Map keys must be strings, sorted by byte length then lexicographically
//! - No duplicate map keys
//! - CIDs encoded with CBOR tag 42 and leading 0x00 byte

use std::collections::BTreeMap;

use atproto_lex_data::{Cid, LexValue};

use crate::error::CborError;

/// CBOR tag number for CIDs (per DAG-CBOR spec).
const CID_CBOR_TAG: u64 = 42;

/// Encode a LexValue to DAG-CBOR bytes.
///
/// Enforces AT Protocol data model constraints:
/// - Only string map keys
/// - Integer numbers only (no floats)
/// - CIDs encoded with tag 42 and 0x00 prefix
/// - Map keys sorted by byte length, then lexicographically
pub fn encode(value: &LexValue) -> Result<Vec<u8>, CborError> {
    let cbor_value = lex_to_cbor(value)?;
    let mut buf = Vec::new();
    ciborium::into_writer(&cbor_value, &mut buf).map_err(|e| CborError::Encode(e.to_string()))?;
    Ok(buf)
}

/// Decode DAG-CBOR bytes to a LexValue.
///
/// Validates AT Protocol data model constraints:
/// - Rejects float values (NaN, Infinity, non-integer floats)
/// - Rejects non-string map keys
/// - Rejects duplicate map keys
/// - Decodes CBOR tag 42 as CIDs
pub fn decode(bytes: &[u8]) -> Result<LexValue, CborError> {
    let cbor_value: ciborium::Value =
        ciborium::from_reader(bytes).map_err(|e| CborError::Decode(e.to_string()))?;
    cbor_to_lex(cbor_value)
}

/// Decode all concatenated DAG-CBOR values from a byte buffer.
///
/// Useful for processing CAR file blocks or event streams containing
/// multiple back-to-back CBOR-encoded values.
pub fn decode_all(bytes: &[u8]) -> Result<Vec<LexValue>, CborError> {
    let mut results = Vec::new();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let cbor_value: ciborium::Value =
            ciborium::from_reader(&mut remaining).map_err(|e| CborError::Decode(e.to_string()))?;
        results.push(cbor_to_lex(cbor_value)?);
    }
    Ok(results)
}

/// Compute the CID for a LexValue by encoding to DAG-CBOR and hashing with SHA-256.
pub fn cid_for_lex(value: &LexValue) -> Result<Cid, CborError> {
    let cbor_bytes = encode(value)?;
    Ok(Cid::for_cbor(&cbor_bytes))
}

/// Convert a LexValue to a ciborium CBOR Value for encoding.
fn lex_to_cbor(value: &LexValue) -> Result<ciborium::Value, CborError> {
    match value {
        LexValue::Null => Ok(ciborium::Value::Null),
        LexValue::Bool(b) => Ok(ciborium::Value::Bool(*b)),
        LexValue::Integer(n) => Ok(ciborium::Value::Integer((*n).into())),
        LexValue::String(s) => Ok(ciborium::Value::Text(s.clone())),
        LexValue::Bytes(b) => Ok(ciborium::Value::Bytes(b.clone())),
        LexValue::Cid(cid) => {
            // CIDs are encoded as CBOR Tag 42 containing bytes with a 0x00 prefix
            let cid_bytes = cid.to_bytes();
            let mut prefixed = Vec::with_capacity(1 + cid_bytes.len());
            prefixed.push(0x00); // Leading 0x00 for historical reasons
            prefixed.extend_from_slice(&cid_bytes);
            Ok(ciborium::Value::Tag(
                CID_CBOR_TAG,
                Box::new(ciborium::Value::Bytes(prefixed)),
            ))
        }
        LexValue::Array(arr) => {
            let items: Result<Vec<_>, _> = arr.iter().map(lex_to_cbor).collect();
            Ok(ciborium::Value::Array(items?))
        }
        LexValue::Map(map) => {
            // DAG-CBOR requires keys sorted by:
            // 1. Byte length (shorter first)
            // 2. Lexicographic byte order (for same-length keys)
            let mut sorted_keys: Vec<&String> = map.keys().collect();
            sorted_keys.sort_by(|a, b| {
                a.len()
                    .cmp(&b.len())
                    .then_with(|| a.as_bytes().cmp(b.as_bytes()))
            });

            let mut entries = Vec::with_capacity(map.len());
            for key in sorted_keys {
                let val = lex_to_cbor(map.get(key).unwrap())?;
                entries.push((ciborium::Value::Text(key.clone()), val));
            }
            Ok(ciborium::Value::Map(entries))
        }
    }
}

/// Convert a ciborium CBOR Value back to a LexValue.
fn cbor_to_lex(value: ciborium::Value) -> Result<LexValue, CborError> {
    match value {
        ciborium::Value::Null => Ok(LexValue::Null),
        ciborium::Value::Bool(b) => Ok(LexValue::Bool(b)),
        ciborium::Value::Integer(n) => {
            let i: i128 = n.into();
            let i64_val = i64::try_from(i)
                .map_err(|_| CborError::Decode("Integer out of i64 range".into()))?;
            Ok(LexValue::Integer(i64_val))
        }
        ciborium::Value::Float(f) => {
            // AT Data Model doesn't support floats.
            // Some CBOR encoders may encode integers as floats, so accept exact integers.
            if f.is_nan() || f.is_infinite() {
                return Err(CborError::FloatNotSupported);
            }
            if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
                Ok(LexValue::Integer(f as i64))
            } else {
                Err(CborError::FloatNotSupported)
            }
        }
        ciborium::Value::Bytes(b) => Ok(LexValue::Bytes(b)),
        ciborium::Value::Text(s) => Ok(LexValue::String(s)),
        ciborium::Value::Array(arr) => {
            let items: Result<Vec<_>, _> = arr.into_iter().map(cbor_to_lex).collect();
            Ok(LexValue::Array(items?))
        }
        ciborium::Value::Map(entries) => {
            let mut map = BTreeMap::new();
            for (k, v) in entries {
                let key = match k {
                    ciborium::Value::Text(s) => s,
                    _ => return Err(CborError::NonStringKey),
                };
                if map.contains_key(&key) {
                    return Err(CborError::DuplicateKey(key));
                }
                map.insert(key, cbor_to_lex(v)?);
            }
            Ok(LexValue::Map(map))
        }
        ciborium::Value::Tag(CID_CBOR_TAG, inner) => match *inner {
            ciborium::Value::Bytes(bytes) => {
                if bytes.is_empty() || bytes[0] != 0x00 {
                    return Err(CborError::InvalidCid(
                        "Expected leading 0x00 byte".to_string(),
                    ));
                }
                let cid = Cid::from_bytes(&bytes[1..])
                    .map_err(|e| CborError::InvalidCid(e.to_string()))?;
                Ok(LexValue::Cid(cid))
            }
            _ => Err(CborError::InvalidCid(
                "Tag 42 must contain bytes".to_string(),
            )),
        },
        ciborium::Value::Tag(_, inner) => {
            // Unknown tags: decode the inner value
            cbor_to_lex(*inner)
        }
        other => Err(CborError::Decode(format!(
            "Unsupported CBOR value type: {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn roundtrip_null() {
        let val = LexValue::Null;
        let encoded = encode(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_bool() {
        for b in [true, false] {
            let val = LexValue::Bool(b);
            let encoded = encode(&val).unwrap();
            let decoded = decode(&encoded).unwrap();
            assert_eq!(val, decoded);
        }
    }

    #[test]
    fn roundtrip_integer() {
        for n in [0i64, 1, -1, 42, 123, -999, i64::MAX, i64::MIN] {
            let val = LexValue::Integer(n);
            let encoded = encode(&val).unwrap();
            let decoded = decode(&encoded).unwrap();
            assert_eq!(val, decoded);
        }
    }

    #[test]
    fn roundtrip_string() {
        for s in ["", "hello", "a~öñ©⽘☎𓋓😀👨\u{200d}👩\u{200d}👧\u{200d}👧"] {
            let val = LexValue::String(s.to_string());
            let encoded = encode(&val).unwrap();
            let decoded = decode(&encoded).unwrap();
            assert_eq!(val, decoded);
        }
    }

    #[test]
    fn roundtrip_bytes() {
        let val = LexValue::Bytes(vec![156, 81, 17, 142, 242, 203, 139, 15]);
        let encoded = encode(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_cid() {
        let cid = Cid::for_cbor(b"test data");
        let val = LexValue::Cid(cid);
        let encoded = encode(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_array() {
        let val = LexValue::Array(vec![
            LexValue::String("abc".into()),
            LexValue::String("def".into()),
            LexValue::String("ghi".into()),
        ]);
        let encoded = encode(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_map() {
        let mut map = BTreeMap::new();
        map.insert("string".to_string(), LexValue::String("abc".into()));
        map.insert("number".to_string(), LexValue::Integer(123));
        map.insert("bool".to_string(), LexValue::Bool(true));
        let val = LexValue::Map(map);
        let encoded = encode(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn map_keys_sorted_by_length_then_lex() {
        // DAG-CBOR sorts keys by byte length first, then lexicographically.
        // "z" (len 1) should come before "ab" (len 2) even though 'z' > 'a'.
        let mut map = BTreeMap::new();
        map.insert("ab".to_string(), LexValue::Integer(1));
        map.insert("z".to_string(), LexValue::Integer(2));
        map.insert("abc".to_string(), LexValue::Integer(3));
        let val = LexValue::Map(map);

        let encoded = encode(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(val, decoded);

        // Verify the encoded order by decoding the raw CBOR
        let cbor_value: ciborium::Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        if let ciborium::Value::Map(entries) = cbor_value {
            let keys: Vec<String> = entries
                .into_iter()
                .map(|(k, _)| match k {
                    ciborium::Value::Text(s) => s,
                    _ => panic!("expected text key"),
                })
                .collect();
            assert_eq!(keys, vec!["z", "ab", "abc"]);
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn cid_tag_42_encoding() {
        let cid = Cid::for_cbor(b"hello");
        let val = LexValue::Cid(cid.clone());
        let encoded = encode(&val).unwrap();

        // Verify raw CBOR contains tag 42
        let cbor_value: ciborium::Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        match cbor_value {
            ciborium::Value::Tag(42, inner) => match *inner {
                ciborium::Value::Bytes(bytes) => {
                    assert_eq!(bytes[0], 0x00, "CID should have leading 0x00");
                    let parsed_cid = Cid::from_bytes(&bytes[1..]).unwrap();
                    assert_eq!(cid, parsed_cid);
                }
                _ => panic!("expected bytes inside tag 42"),
            },
            _ => panic!("expected tag 42"),
        }
    }

    #[test]
    fn decode_all_multiple_values() {
        let val1 = LexValue::String("first".into());
        let val2 = LexValue::Integer(42);
        let val3 = LexValue::Bool(true);

        let mut combined = Vec::new();
        combined.extend(encode(&val1).unwrap());
        combined.extend(encode(&val2).unwrap());
        combined.extend(encode(&val3).unwrap());

        let decoded = decode_all(&combined).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], val1);
        assert_eq!(decoded[1], val2);
        assert_eq!(decoded[2], val3);
    }

    #[test]
    fn cid_for_lex_deterministic() {
        let mut map = BTreeMap::new();
        map.insert("text".to_string(), LexValue::String("hello".into()));
        map.insert("count".to_string(), LexValue::Integer(42));
        let val = LexValue::Map(map);

        let cid1 = cid_for_lex(&val).unwrap();
        let cid2 = cid_for_lex(&val).unwrap();
        assert_eq!(cid1, cid2, "CID should be deterministic");
    }

    #[test]
    fn nested_structure_roundtrip() {
        let cid = Cid::for_cbor(b"nested");
        let mut inner_map = BTreeMap::new();
        inner_map.insert("cid".to_string(), LexValue::Cid(cid));
        inner_map.insert("bytes".to_string(), LexValue::Bytes(vec![1, 2, 3, 4]));

        let mut outer_map = BTreeMap::new();
        outer_map.insert(
            "array".to_string(),
            LexValue::Array(vec![
                LexValue::Map(inner_map),
                LexValue::String("item".into()),
            ]),
        );
        outer_map.insert("null".to_string(), LexValue::Null);

        let val = LexValue::Map(outer_map);
        let encoded = encode(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn basic_test_vector() {
        // Test against the "basic" vector from the TS test suite.
        let expected_cbor: &[u8] = &[
            167, 100, 98, 111, 111, 108, 245, 100, 110, 117, 108, 108, 246, 101, 97, 114, 114, 97,
            121, 131, 99, 97, 98, 99, 99, 100, 101, 102, 99, 103, 104, 105, 102, 111, 98, 106, 101,
            99, 116, 164, 99, 97, 114, 114, 131, 99, 97, 98, 99, 99, 100, 101, 102, 99, 103, 104,
            105, 100, 98, 111, 111, 108, 245, 102, 110, 117, 109, 98, 101, 114, 24, 123, 102, 115,
            116, 114, 105, 110, 103, 99, 97, 98, 99, 102, 115, 116, 114, 105, 110, 103, 99, 97, 98,
            99, 103, 105, 110, 116, 101, 103, 101, 114, 24, 123, 103, 117, 110, 105, 99, 111, 100,
            101, 120, 47, 97, 126, 195, 182, 195, 177, 194, 169, 226, 189, 152, 226, 152, 142, 240,
            147, 139, 147, 240, 159, 152, 128, 240, 159, 145, 168, 226, 128, 141, 240, 159, 145,
            169, 226, 128, 141, 240, 159, 145, 167, 226, 128, 141, 240, 159, 145, 167,
        ];
        let expected_cid = "bafyreiclp443lavogvhj3d2ob2cxbfuscni2k5jk7bebjzg7khl3esabwq";

        // Build the LexValue
        let mut inner_obj = BTreeMap::new();
        inner_obj.insert("string".to_string(), LexValue::String("abc".into()));
        inner_obj.insert("number".to_string(), LexValue::Integer(123));
        inner_obj.insert("bool".to_string(), LexValue::Bool(true));
        inner_obj.insert(
            "arr".to_string(),
            LexValue::Array(vec![
                LexValue::String("abc".into()),
                LexValue::String("def".into()),
                LexValue::String("ghi".into()),
            ]),
        );

        let mut map = BTreeMap::new();
        map.insert("string".to_string(), LexValue::String("abc".into()));
        map.insert(
            "unicode".to_string(),
            LexValue::String("a~öñ©⽘☎𓋓😀👨\u{200d}👩\u{200d}👧\u{200d}👧".into()),
        );
        map.insert("integer".to_string(), LexValue::Integer(123));
        map.insert("bool".to_string(), LexValue::Bool(true));
        map.insert("null".to_string(), LexValue::Null);
        map.insert(
            "array".to_string(),
            LexValue::Array(vec![
                LexValue::String("abc".into()),
                LexValue::String("def".into()),
                LexValue::String("ghi".into()),
            ]),
        );
        map.insert("object".to_string(), LexValue::Map(inner_obj));

        let val = LexValue::Map(map);

        // Encode and verify bytes match
        let encoded = encode(&val).unwrap();
        assert_eq!(
            encoded, expected_cbor,
            "Encoded CBOR should match test vector"
        );

        // Verify CID matches
        let cid = cid_for_lex(&val).unwrap();
        assert_eq!(
            cid.to_string(),
            expected_cid,
            "CID should match test vector"
        );

        // Verify decode roundtrip
        let decoded = decode(&encoded).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn ipld_test_vector() {
        // Test against the "ipld" vector from the TS test suite.
        let expected_cbor: &[u8] = &[
            163, 97, 97, 216, 42, 88, 37, 0, 1, 113, 18, 32, 101, 6, 42, 90, 90, 0, 252, 22, 215,
            60, 105, 68, 35, 124, 203, 193, 91, 28, 74, 114, 52, 72, 147, 54, 137, 29, 9, 23, 65,
            162, 57, 208, 97, 98, 88, 32, 156, 81, 17, 142, 242, 203, 139, 15, 106, 155, 142, 73,
            174, 161, 253, 65, 60, 242, 11, 98, 238, 213, 118, 248, 157, 238, 190, 176, 26, 194,
            204, 141, 97, 99, 164, 99, 114, 101, 102, 216, 42, 88, 37, 0, 1, 85, 18, 32, 66, 88,
            207, 255, 120, 246, 19, 105, 118, 151, 86, 63, 146, 108, 145, 229, 211, 87, 77, 46,
            162, 90, 231, 237, 146, 214, 235, 252, 35, 163, 136, 158, 100, 115, 105, 122, 101, 25,
            39, 16, 101, 36, 116, 121, 112, 101, 100, 98, 108, 111, 98, 104, 109, 105, 109, 101,
            84, 121, 112, 101, 106, 105, 109, 97, 103, 101, 47, 106, 112, 101, 103,
        ];
        let expected_cid = "bafyreihldkhcwijkde7gx4rpkkuw7pl6lbyu5gieunyc7ihactn5bkd2nm";

        let cid_a: Cid = "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"
            .parse()
            .unwrap();
        let cid_ref: Cid = "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity"
            .parse()
            .unwrap();

        let mut blob_map = BTreeMap::new();
        blob_map.insert("$type".to_string(), LexValue::String("blob".into()));
        blob_map.insert("ref".to_string(), LexValue::Cid(cid_ref));
        blob_map.insert(
            "mimeType".to_string(),
            LexValue::String("image/jpeg".into()),
        );
        blob_map.insert("size".to_string(), LexValue::Integer(10000));

        let mut map = BTreeMap::new();
        map.insert("a".to_string(), LexValue::Cid(cid_a));
        map.insert(
            "b".to_string(),
            LexValue::Bytes(vec![
                156, 81, 17, 142, 242, 203, 139, 15, 106, 155, 142, 73, 174, 161, 253, 65, 60, 242,
                11, 98, 238, 213, 118, 248, 157, 238, 190, 176, 26, 194, 204, 141,
            ]),
        );
        map.insert("c".to_string(), LexValue::Map(blob_map));

        let val = LexValue::Map(map);

        let encoded = encode(&val).unwrap();
        assert_eq!(
            encoded, expected_cbor,
            "Encoded CBOR should match IPLD test vector"
        );

        let cid = cid_for_lex(&val).unwrap();
        assert_eq!(cid.to_string(), expected_cid);

        let decoded = decode(&encoded).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn ipld_array_test_vector() {
        let expected_cid = "bafyreiaj3udmqlqrcbjxjayzuxwp64gt64olcbjfrkldzoqponpru6gq4m";

        let cids = [
            "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a",
            "bafyreigoxt64qghytzkr6ik7qvtzc7lyytiq5xbbrokbxjows2wp7vmo6q",
            "bafyreiaizynclnqiolq7byfpjjtgqzn4sfrsgn7z2hhf6bo4utdwkin7ke",
            "bafyreifd4w4tcr5tluxz7osjtnofffvtsmgdqcfrfi6evjde4pl27lrjpy",
        ];

        let val = LexValue::Array(
            cids.iter()
                .map(|s| LexValue::Cid(s.parse().unwrap()))
                .collect(),
        );

        let encoded = encode(&val).unwrap();
        let cid = cid_for_lex(&val).unwrap();
        assert_eq!(cid.to_string(), expected_cid);

        let decoded = decode(&encoded).unwrap();
        assert_eq!(val, decoded);
    }
}
