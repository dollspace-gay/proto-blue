use proptest::prelude::*;
use std::collections::BTreeMap;

use proto_blue_lex_data::{BlobRef, Cid, LexValue};

proptest! {
    /// LexValue::type_name() never returns an empty string.
    /// It returns None when there is no $type key or the value is not a map,
    /// and Some(non-empty) when the $type key holds a non-empty string.
    #[test]
    fn type_name_never_empty(type_str in ".+") {
        let mut map = BTreeMap::new();
        map.insert("$type".to_string(), LexValue::String(type_str));
        let val = LexValue::Map(map);
        let name = val.type_name();
        prop_assert!(name.is_some());
        prop_assert!(!name.unwrap().is_empty());
    }

    /// LexValue::is_scalar() is consistent:
    /// Null, Bool, Integer, String, Bytes, Cid are scalar; Array and Map are not.
    #[test]
    fn is_scalar_consistency(
        b in any::<bool>(),
        i in any::<i64>(),
        s in ".*",
        bytes in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        // Scalar types
        prop_assert!(LexValue::Null.is_scalar());
        prop_assert!(LexValue::Bool(b).is_scalar());
        prop_assert!(LexValue::Integer(i).is_scalar());
        prop_assert!(LexValue::String(s).is_scalar());
        prop_assert!(LexValue::Bytes(bytes).is_scalar());
        let cid = Cid::for_cbor(b"test");
        prop_assert!(LexValue::Cid(cid).is_scalar());

        // Non-scalar types
        prop_assert!(!LexValue::Array(vec![]).is_scalar());
        prop_assert!(!LexValue::Map(BTreeMap::new()).is_scalar());
    }

    /// Cid string roundtrip: Cid::from_str(cid.to_string()) == original.
    #[test]
    fn cid_string_roundtrip(data in prop::collection::vec(any::<u8>(), 1..128)) {
        let cid = Cid::for_cbor(&data);
        let s = cid.to_string();
        let parsed: Cid = s.parse().unwrap();
        prop_assert_eq!(cid, parsed);
    }

    /// BlobRef construction never panics for arbitrary inputs.
    #[test]
    fn blob_ref_construction_no_panic(
        data in prop::collection::vec(any::<u8>(), 1..64),
        mime in "[a-z]{1,10}/[a-z]{1,10}",
        size in any::<u64>(),
    ) {
        let cid = Cid::for_raw(&data);
        let blob = BlobRef::new(cid, mime.clone(), size);
        // Should never panic
        let _ = blob.is_valid();
        let _ = blob.is_strict_ref();
        prop_assert_eq!(blob.size(), Some(size));
        prop_assert_eq!(blob.mime_type(), mime.as_str());
    }
}
