//! Property-based tests for proto-blue-syntax types.

use proptest::prelude::*;

// --- DID property tests ---

proptest! {
    #[test]
    fn valid_did_roundtrips_through_display_parse(
        method in "[a-z]{3,10}",
        id in "[a-zA-Z0-9._:%-]{1,200}"
    ) {
        let did_str = format!("did:{method}:{id}");
        if let Ok(did) = proto_blue_syntax::Did::new(&did_str) {
            // Display should produce the same string
            prop_assert_eq!(did.to_string(), did_str);
            // Re-parsing should succeed
            let reparsed = proto_blue_syntax::Did::new(did.as_str()).unwrap();
            prop_assert_eq!(reparsed.to_string(), did.to_string());
        }
    }

    #[test]
    fn did_never_panics_on_arbitrary_input(s in ".*") {
        // Should never panic, just return Ok or Err
        let _ = proto_blue_syntax::Did::new(&s);
    }
}

// --- Handle property tests ---

proptest! {
    #[test]
    fn valid_handle_is_lowercase(
        segments in proptest::collection::vec("[a-z0-9]{1,20}", 2..5)
    ) {
        let handle_str = segments.join(".");
        if let Ok(handle) = proto_blue_syntax::Handle::new(&handle_str) {
            // Handles are normalized to lowercase
            prop_assert_eq!(handle.to_string(), handle_str.to_lowercase());
        }
    }

    #[test]
    fn handle_never_panics_on_arbitrary_input(s in ".*") {
        let _ = proto_blue_syntax::Handle::new(&s);
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
        if let Ok(nsid) = proto_blue_syntax::Nsid::new(&nsid_str) {
            let display = nsid.to_string();
            // Name should be the last segment
            prop_assert!(display.ends_with(&name));
            prop_assert_eq!(display, nsid_str);
        }
    }

    #[test]
    fn nsid_never_panics(s in ".*") {
        let _ = proto_blue_syntax::Nsid::new(&s);
    }
}

// --- TID property tests ---

proptest! {
    #[test]
    fn tid_from_timestamp_roundtrip(ts_us in 0u64..=(1u64 << 53)) {
        let tid = proto_blue_syntax::Tid::from_timestamp(ts_us, 0);
        let s = tid.to_string();
        let reparsed = proto_blue_syntax::Tid::new(&s).unwrap();
        prop_assert_eq!(reparsed.to_string(), s);
    }

    #[test]
    fn tid_string_is_always_13_chars(ts_us in 0u64..=(1u64 << 53)) {
        let tid = proto_blue_syntax::Tid::from_timestamp(ts_us, 0);
        prop_assert_eq!(tid.to_string().len(), 13);
    }

    #[test]
    fn tid_never_panics(s in "[a-z2-7]{0,20}") {
        let _ = proto_blue_syntax::Tid::new(&s);
    }
}

// --- AT-URI property tests ---

proptest! {
    #[test]
    fn aturi_never_panics(s in ".*") {
        let _ = proto_blue_syntax::AtUri::new(&s);
    }

    #[test]
    fn valid_aturi_roundtrip(
        did_method in "[a-z]{3,8}",
        did_id in "[a-zA-Z0-9]{3,30}",
        collection in "[a-z]{2,10}\\.[a-z]{2,10}\\.[a-z]{2,20}",
        rkey in "[a-zA-Z0-9]{1,15}"
    ) {
        let uri = format!("at://did:{did_method}:{did_id}/{collection}/{rkey}");
        if let Ok(parsed) = proto_blue_syntax::AtUri::new(&uri) {
            prop_assert_eq!(parsed.to_string(), uri);
        }
    }
}

// --- RecordKey property tests ---

proptest! {
    #[test]
    fn recordkey_never_panics(s in ".*") {
        let _ = proto_blue_syntax::RecordKey::new(&s);
    }

    #[test]
    fn valid_recordkey_roundtrip(s in "[a-zA-Z0-9._~:@!$&'*+,;=-]{1,512}") {
        if let Ok(rk) = proto_blue_syntax::RecordKey::new(&s) {
            prop_assert_eq!(rk.to_string(), s);
        }
    }

    /// `.` and `..` are reserved (they'd collide with filesystem /
    /// URL conventions) — both must be rejected regardless of what
    /// else might look valid.
    #[test]
    fn recordkey_rejects_dot_and_dotdot(_: ()) {
        prop_assert!(proto_blue_syntax::RecordKey::new(".").is_err());
        prop_assert!(proto_blue_syntax::RecordKey::new("..").is_err());
    }

    /// 513+ byte inputs exceed the spec limit (512). Any such input
    /// must be rejected; any 1-512 byte valid-character input must
    /// round-trip.
    #[test]
    fn recordkey_length_bounds(n in 1usize..=600) {
        let s: String = "a".repeat(n);
        let parsed = proto_blue_syntax::RecordKey::new(&s);
        if n <= 512 {
            prop_assert!(parsed.is_ok(), "len={n} should parse");
        } else {
            prop_assert!(parsed.is_err(), "len={n} should reject");
        }
    }
}

// --- Handle normalization idempotency + TLD rules ---

proptest! {
    /// Normalization must be idempotent: applying it twice produces
    /// the same result as applying it once. This is the contract that
    /// lets upstream callers memoize / cache normalized handles.
    #[test]
    fn handle_normalize_is_idempotent(s in ".*") {
        let n1 = proto_blue_syntax::normalize_handle(&s);
        let n2 = proto_blue_syntax::normalize_handle(&n1);
        prop_assert_eq!(n1, n2);
    }

    /// Non-ASCII strings are never valid handles — atproto handles
    /// are case-folded ASCII per spec.
    #[test]
    fn handle_rejects_non_ascii(prefix in "[a-z]{1,10}", suffix in "[a-z]{1,10}") {
        let with_emoji = format!("{prefix}🚀{suffix}.test");
        prop_assert!(proto_blue_syntax::Handle::new(&with_emoji).is_err());
    }

    /// `normalize_and_ensure_valid_handle` must agree with
    /// `Handle::new(&normalize_handle(_))` on the accept/reject
    /// decision — same pipeline, different entry points.
    #[test]
    fn handle_normalize_ensure_matches_direct(s in ".*") {
        let combined = proto_blue_syntax::normalize_and_ensure_valid_handle(&s);
        let direct = proto_blue_syntax::Handle::new(
            &proto_blue_syntax::normalize_handle(&s)
        );
        prop_assert_eq!(combined.is_ok(), direct.is_ok());
    }
}

// --- DID method-specific round-trips ---

proptest! {
    /// did:plc identifiers are 24-char base32 strings following
    /// `did:plc:`. Round-trip must preserve the method tag + id.
    #[test]
    fn did_plc_roundtrip(id in "[a-z2-7]{24}") {
        let s = format!("did:plc:{id}");
        let did = proto_blue_syntax::Did::new(&s).unwrap();
        prop_assert_eq!(did.to_string(), s);
    }

    /// did:web encodes a hostname after `did:web:` (percent-encoded
    /// `%3A` for a port if present).
    #[test]
    fn did_web_roundtrip(host in "[a-z][a-z0-9-]{0,20}\\.[a-z]{2,6}") {
        let s = format!("did:web:{host}");
        let did = proto_blue_syntax::Did::new(&s).unwrap();
        prop_assert_eq!(did.to_string(), s);
    }
}

// --- AT-URI builder + setter invariants ---

proptest! {
    /// `AtUri::make` → `parse` round-trip: a URI built from its
    /// components must parse back to one with equivalent components.
    #[test]
    fn aturi_make_then_parse_roundtrip(
        did_id in "[a-zA-Z0-9]{3,30}",
        collection in proptest::option::of("[a-z]{2,10}\\.[a-z]{2,10}\\.[a-z]{2,20}"),
        rkey in proptest::option::of("[a-zA-Z0-9]{1,15}"),
    ) {
        // `make` takes rkey only when collection is Some.
        let authority = format!("did:plc:{did_id}");
        let (collection_opt, rkey_opt) = match (&collection, &rkey) {
            (Some(c), Some(r)) => (Some(c.as_str()), Some(r.as_str())),
            _ => (collection.as_deref(), None),
        };
        if let Ok(uri) = proto_blue_syntax::AtUri::make(&authority, collection_opt, rkey_opt) {
            let s = uri.to_string();
            let reparsed = proto_blue_syntax::AtUri::new(&s).unwrap();
            prop_assert_eq!(reparsed.authority(), &authority);
            prop_assert_eq!(reparsed.collection(), collection_opt);
            prop_assert_eq!(reparsed.rkey(), rkey_opt);
        }
    }

    /// Setting a fragment must not change any other component.
    #[test]
    fn aturi_set_fragment_preserves_other_components(
        did_id in "[a-zA-Z0-9]{5,20}",
        collection in "[a-z]{2,10}\\.[a-z]{2,10}\\.[a-z]{2,15}",
        rkey in "[a-zA-Z0-9]{1,15}",
        fragment in proptest::option::of("/[a-zA-Z0-9_/-]{1,30}"),
    ) {
        let s = format!("at://did:plc:{did_id}/{collection}/{rkey}");
        let mut uri = proto_blue_syntax::AtUri::new(&s).unwrap();
        let before_authority = uri.authority().to_string();
        let before_collection = uri.collection().map(str::to_string);
        let before_rkey = uri.rkey().map(str::to_string);

        if uri.set_fragment(fragment.as_deref()).is_ok() {
            prop_assert_eq!(uri.authority(), &before_authority);
            prop_assert_eq!(uri.collection().map(str::to_string), before_collection);
            prop_assert_eq!(uri.rkey().map(str::to_string), before_rkey);
            prop_assert_eq!(uri.fragment(), fragment.as_deref());
        }
    }
}

// --- TID timestamp-extraction round-trip ---

proptest! {
    /// `from_timestamp(ts).timestamp_micros() == ts`. Without this
    /// invariant, TID-based ordering would drift from wall-clock
    /// ordering.
    #[test]
    fn tid_timestamp_extraction_roundtrip(ts_us in 0u64..=(1u64 << 53)) {
        let tid = proto_blue_syntax::Tid::from_timestamp(ts_us, 0);
        prop_assert_eq!(tid.timestamp_micros(), ts_us);
    }

    /// For any two timestamps `a < b` (and the same clock id), the
    /// resulting TIDs must sort `a < b` lexicographically. Sort-
    /// order consistency is the whole reason TIDs exist.
    #[test]
    fn tid_preserves_timestamp_ordering(
        a in 0u64..=(1u64 << 40),
        b in 0u64..=(1u64 << 40),
    ) {
        prop_assume!(a != b);
        let (earlier, later) = if a < b { (a, b) } else { (b, a) };
        let t_earlier = proto_blue_syntax::Tid::from_timestamp(earlier, 0);
        let t_later = proto_blue_syntax::Tid::from_timestamp(later, 0);
        prop_assert!(
            t_earlier.as_str() < t_later.as_str(),
            "earlier={} later={} t_earlier={} t_later={}",
            earlier, later, t_earlier.as_str(), t_later.as_str()
        );
    }
}

// --- Language tag normalization ---

proptest! {
    /// `is_valid_language` must never panic.
    #[test]
    fn is_valid_language_never_panics(s in ".*") {
        let _ = proto_blue_syntax::is_valid_language(&s);
    }

    /// BCP-47 language tags validated by `is_valid_language` are
    /// case-insensitive, so ASCII-uppercasing a valid tag must also
    /// validate.
    #[test]
    fn is_valid_language_is_case_insensitive(
        lang in "[a-z]{2,3}",
    ) {
        if proto_blue_syntax::is_valid_language(&lang) {
            prop_assert!(proto_blue_syntax::is_valid_language(&lang.to_uppercase()));
        }
    }
}
