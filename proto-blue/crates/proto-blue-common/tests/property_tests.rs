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

    /// For any DID document that carries a `#atproto_pds` service
    /// entry with type `AtprotoPersonalDataServer` and a valid
    /// endpoint URL, `get_pds_endpoint` must return that URL.
    /// Without this invariant, handle-to-PDS resolution silently
    /// misses valid PDSes.
    ///
    /// Host form is constrained to two labels each matching
    /// `[a-z][a-z0-9-]*[a-z0-9]?` so the generated URL validates —
    /// `get_pds_endpoint` parses the endpoint through a real URL
    /// validator that rejects digit-only TLDs and other malformed
    /// hostnames.
    #[test]
    fn did_document_get_pds_endpoint_extracts_atproto_pds(
        did_id in "[a-z][a-z0-9]{2,20}",
        host_label in "[a-z][a-z0-9]{2,15}",
        tld in "[a-z]{2,6}",
    ) {
        let endpoint = format!("https://{host_label}.{tld}");
        let doc = DidDocument {
            id: format!("did:plc:{did_id}"),
            also_known_as: vec![],
            verification_method: vec![],
            service: vec![proto_blue_common::did_doc::Service {
                id: "#atproto_pds".into(),
                service_type: "AtprotoPersonalDataServer".into(),
                service_endpoint: serde_json::Value::String(endpoint.clone()),
            }],
        };
        prop_assert_eq!(get_pds_endpoint(&doc), Some(endpoint.clone()));
    }

    /// A DID document with no services returns `None`, no matter what
    /// other fields are set.
    #[test]
    fn did_document_get_pds_endpoint_returns_none_without_service(
        did_id in "[a-z][a-z0-9]{2,20}",
    ) {
        let doc = DidDocument {
            id: format!("did:plc:{did_id}"),
            also_known_as: vec![],
            verification_method: vec![],
            service: vec![],
        };
        prop_assert_eq!(get_pds_endpoint(&doc), None);
    }
}
