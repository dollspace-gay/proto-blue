use proptest::prelude::*;

use proto_blue_common::{
    DidDocument, get_pds_endpoint, grapheme_len, next_tid, s32_decode, s32_encode,
};

proptest! {
    /// next_tid() always returns 13-char strings matching the base32-sortable TID pattern.
    #[test]
    fn tid_generation_always_valid(_ in 0..100u32) {
        let tid = next_tid(None);
        let s = tid.as_str();
        prop_assert_eq!(s.len(), 13);
        // Every character must be in the base32-sortable charset [2-7a-z]
        for ch in s.chars() {
            prop_assert!(
                ('2'..='7').contains(&ch) || ch.is_ascii_lowercase(),
                "TID character '{}' not in [2-7a-z]", ch
            );
        }
    }

    /// Sequential next_tid() calls produce lexicographically sorted strings.
    #[test]
    fn tid_monotonicity(_ in 0..50u32) {
        let t1 = next_tid(None);
        let t2 = next_tid(None);
        prop_assert!(
            t2.as_str() > t1.as_str(),
            "Expected t2 ({}) > t1 ({})", t2.as_str(), t1.as_str()
        );
    }

    /// grapheme_len() is always <= byte length for any valid string.
    #[test]
    fn grapheme_len_le_byte_len(s in ".*") {
        let g = grapheme_len(&s);
        let b = s.len();
        prop_assert!(
            g <= b,
            "grapheme_len ({}) > byte len ({}) for {:?}", g, b, s
        );
    }

    /// s32_encode/s32_decode roundtrip for random u64 values.
    /// Note: s32_encode(0) returns "" which decodes to 0, so roundtrip holds.
    #[test]
    fn s32_roundtrip(val in any::<u64>()) {
        let encoded = s32_encode(val);
        let decoded = s32_decode(&encoded);
        if val == 0 {
            // 0 encodes to empty string, which decodes back to 0
            prop_assert_eq!(decoded, 0);
        } else {
            prop_assert_eq!(decoded, val, "s32 roundtrip failed for {}", val);
        }
    }

    /// get_pds_endpoint never panics on arbitrary DidDocument fields.
    #[test]
    fn did_document_get_pds_endpoint_no_panic(
        id in "[a-z0-9:]{3,50}",
        also_known_as in prop::collection::vec("[a-z://]{0,30}", 0..3),
        service_id in "[a-z#_]{1,20}",
        service_type in "[A-Za-z]{1,30}",
        service_endpoint in "[a-z0-9://.]{0,50}",
    ) {
        let doc = DidDocument {
            id,
            also_known_as,
            verification_method: vec![],
            service: vec![proto_blue_common::did_doc::Service {
                id: service_id,
                service_type,
                service_endpoint: serde_json::Value::String(service_endpoint),
            }],
        };
        // Should never panic -- result may be Some or None
        let _ = get_pds_endpoint(&doc);
    }
}
