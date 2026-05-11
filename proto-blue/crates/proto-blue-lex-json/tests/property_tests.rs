#![allow(clippy::pedantic, clippy::nursery)]

use proptest::prelude::*;

use proto_blue_lex_data::LexValue;
use proto_blue_lex_json::{json_to_lex, lex_to_json};

proptest! {
    /// json_to_lex(lex_to_json(value)) roundtrip for simple values.
    #[test]
    fn roundtrip_null(_ in 0..1u32) {
        let value = LexValue::Null;
        let json = lex_to_json(&value);
        let back = json_to_lex(&json);
        prop_assert_eq!(value, back);
    }

    #[test]
    fn roundtrip_bool(b in any::<bool>()) {
        let value = LexValue::Bool(b);
        let json = lex_to_json(&value);
        let back = json_to_lex(&json);
        prop_assert_eq!(value, back);
    }

    #[test]
    fn roundtrip_integer(n in any::<i64>()) {
        let value = LexValue::Integer(n);
        let json = lex_to_json(&value);
        let back = json_to_lex(&json);
        prop_assert_eq!(value, back);
    }

    #[test]
    fn roundtrip_string(s in ".*") {
        let value = LexValue::String(s);
        let json = lex_to_json(&value);
        let back = json_to_lex(&json);
        prop_assert_eq!(value, back);
    }

    /// Arbitrary valid JSON never panics when passed to json_to_lex.
    #[test]
    fn arbitrary_json_no_panic(
        key in "[a-zA-Z_][a-zA-Z0-9_]{0,20}",
        str_val in ".*",
        int_val in any::<i64>(),
        bool_val in any::<bool>(),
    ) {
        // Build a JSON object with various field types
        let json = serde_json::json!({
            key: str_val,
            "num": int_val,
            "flag": bool_val,
            "null_field": null,
            "arr": [1, 2, "three"],
            "nested": { "a": 1 }
        });
        // Should never panic
        let _ = json_to_lex(&json);
    }
}
