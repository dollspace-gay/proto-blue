//! Property-based tests for atproto-syntax types.

use proptest::prelude::*;

// --- DID property tests ---

proptest! {
    #[test]
    fn valid_did_roundtrips_through_display_parse(
        method in "[a-z]{3,10}",
        id in "[a-zA-Z0-9._:%-]{1,200}"
    ) {
        let did_str = format!("did:{method}:{id}");
        if let Ok(did) = atproto_syntax::Did::new(&did_str) {
            // Display should produce the same string
            prop_assert_eq!(did.to_string(), did_str);
            // Re-parsing should succeed
            let reparsed = atproto_syntax::Did::new(&did.to_string()).unwrap();
            prop_assert_eq!(reparsed.to_string(), did.to_string());
        }
    }

    #[test]
    fn did_never_panics_on_arbitrary_input(s in ".*") {
        // Should never panic, just return Ok or Err
        let _ = atproto_syntax::Did::new(&s);
    }
}

// --- Handle property tests ---

proptest! {
    #[test]
    fn valid_handle_is_lowercase(
        segments in proptest::collection::vec("[a-z0-9]{1,20}", 2..5)
    ) {
        let handle_str = segments.join(".");
        if let Ok(handle) = atproto_syntax::Handle::new(&handle_str) {
            // Handles are normalized to lowercase
            prop_assert_eq!(handle.to_string(), handle_str.to_lowercase());
        }
    }

    #[test]
    fn handle_never_panics_on_arbitrary_input(s in ".*") {
        let _ = atproto_syntax::Handle::new(&s);
    }
}

// --- NSID property tests ---

proptest! {
    #[test]
    fn nsid_authority_name_decomposition(
        authority_parts in proptest::collection::vec("[a-z]{2,10}", 2..4),
        name in "[a-zA-Z]{1,20}"
    ) {
        let nsid_str = format!("{}.{name}", authority_parts.join("."));
        if let Ok(nsid) = atproto_syntax::Nsid::new(&nsid_str) {
            let display = nsid.to_string();
            // Name should be the last segment
            prop_assert!(display.ends_with(&name));
            prop_assert_eq!(display, nsid_str);
        }
    }

    #[test]
    fn nsid_never_panics(s in ".*") {
        let _ = atproto_syntax::Nsid::new(&s);
    }
}

// --- TID property tests ---

proptest! {
    #[test]
    fn tid_from_timestamp_roundtrip(ts_us in 0u64..=(1u64 << 53)) {
        let tid = atproto_syntax::Tid::from_timestamp(ts_us, 0);
        let s = tid.to_string();
        let reparsed = atproto_syntax::Tid::new(&s).unwrap();
        prop_assert_eq!(reparsed.to_string(), s);
    }

    #[test]
    fn tid_string_is_always_13_chars(ts_us in 0u64..=(1u64 << 53)) {
        let tid = atproto_syntax::Tid::from_timestamp(ts_us, 0);
        prop_assert_eq!(tid.to_string().len(), 13);
    }

    #[test]
    fn tid_never_panics(s in "[a-z2-7]{0,20}") {
        let _ = atproto_syntax::Tid::new(&s);
    }
}

// --- AT-URI property tests ---

proptest! {
    #[test]
    fn aturi_never_panics(s in ".*") {
        let _ = atproto_syntax::AtUri::new(&s);
    }

    #[test]
    fn valid_aturi_roundtrip(
        did_method in "[a-z]{3,8}",
        did_id in "[a-zA-Z0-9]{3,30}",
        collection in "[a-z]{2,10}\\.[a-z]{2,10}\\.[a-z]{2,20}",
        rkey in "[a-zA-Z0-9]{1,15}"
    ) {
        let uri = format!("at://did:{did_method}:{did_id}/{collection}/{rkey}");
        if let Ok(parsed) = atproto_syntax::AtUri::new(&uri) {
            prop_assert_eq!(parsed.to_string(), uri);
        }
    }
}

// --- RecordKey property tests ---

proptest! {
    #[test]
    fn recordkey_never_panics(s in ".*") {
        let _ = atproto_syntax::RecordKey::new(&s);
    }

    #[test]
    fn valid_recordkey_roundtrip(s in "[a-zA-Z0-9._~:@!$&'*+,;=-]{1,512}") {
        if let Ok(rk) = atproto_syntax::RecordKey::new(&s) {
            prop_assert_eq!(rk.to_string(), s);
        }
    }
}
