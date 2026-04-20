//! Bidirectional conversion between JSON and `LexValue`.
//!
//! In JSON representation:
//! - CIDs are encoded as `{"$link": "bafy..."}`
//! - Byte arrays are encoded as `{"$bytes": "<base64>"}`
//! - Blob refs are `{"$type": "blob", "ref": {"$link": "..."}, "mimeType": "...", "size": N}`
//!
//! Parsing has two modes controlled by [`LexParseOptions`]:
//!
//! - **Lenient (default)** — malformed `$link`/`$bytes`/unsafe-integer
//!   values silently fall back to plain maps / strings / truncated
//!   integers. Matches pre-0.2.2 behaviour and TS default.
//! - **Strict** — each malformed case returns the matching
//!   [`JsonError`] variant. Mirrors TS `LexParseOptions { strict: true }`.
//!
//! Safe-integer bound: the AT Data Model allows i64 on the wire, but
//! JS safe integers top out at `2^53 - 1`. Strict mode enforces the
//! tighter JS bound so that Rust-to-TS round-trips never silently
//! corrupt large values.

use std::collections::BTreeMap;

use base64::Engine as _;
use proto_blue_lex_data::{Cid, LexValue};
use serde_json::Value as JsonValue;

use crate::error::JsonError;

/// Base64 engine: standard alphabet, no padding, lenient decode.
const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// Upper bound on `$link` string length (matches TS implementation). A
/// CID string longer than this is treated as malformed even before
/// attempting to parse it — protects against adversarial input.
const MAX_LINK_LEN: usize = 2048;

/// Largest JS-safe integer, `2^53 - 1`. Strict mode rejects integers
/// outside `[-MAX, MAX]` so that round-trips through a TypeScript
/// consumer don't silently corrupt.
const JS_SAFE_INTEGER_MAX: i64 = (1i64 << 53) - 1;

/// Options for parsing JSON into a `LexValue`.
///
/// The default is lenient; set `strict: true` to mirror TS
/// `LexParseOptions { strict: true }` behaviour.
#[derive(Debug, Clone, Copy, Default)]
pub struct LexParseOptions {
    /// When `true`, return [`JsonError`] for malformed `$link`,
    /// `$bytes`, non-safe-integer numbers, malformed blob refs, and
    /// `__proto__` keys. When `false` (default), fall back to a plain
    /// map / string / truncated integer.
    pub strict: bool,
}

impl LexParseOptions {
    /// Strict mode — rejects every TS-strict violation.
    #[must_use]
    pub const fn strict() -> Self {
        Self { strict: true }
    }
}

/// Serialize a `LexValue` to a JSON string.
#[must_use]
pub fn lex_stringify(value: &LexValue) -> String {
    let json = lex_to_json(value);
    serde_json::to_string(&json).expect("LexValue should always serialize to valid JSON")
}

/// Parse a JSON string to a `LexValue` (lenient).
pub fn lex_parse(input: &str) -> Result<LexValue, JsonError> {
    lex_parse_with(input, LexParseOptions::default())
}

/// Parse a JSON string to a `LexValue` with caller-supplied options.
pub fn lex_parse_with(input: &str, opts: LexParseOptions) -> Result<LexValue, JsonError> {
    let json: JsonValue = serde_json::from_str(input)?;
    json_to_lex_with(&json, opts)
}

/// Parse a UTF-8 byte slice containing JSON into a `LexValue` (lenient).
///
/// Mirrors TS `lexParseJsonBytes`.
pub fn lex_parse_json_bytes(bytes: &[u8]) -> Result<LexValue, JsonError> {
    lex_parse_json_bytes_with(bytes, LexParseOptions::default())
}

/// Parse a UTF-8 byte slice containing JSON into a `LexValue` with
/// caller-supplied options.
pub fn lex_parse_json_bytes_with(
    bytes: &[u8],
    opts: LexParseOptions,
) -> Result<LexValue, JsonError> {
    let json: JsonValue = serde_json::from_slice(bytes)?;
    json_to_lex_with(&json, opts)
}

/// Convert a JSON value to a `LexValue` (lenient — never fails).
///
/// Recognizes special object patterns:
/// - `{"$link": "..."}` (exactly one key) → `LexValue::Cid`
/// - `{"$bytes": "..."}` (exactly one key) → `LexValue::Bytes`
/// - Objects with `$type`, `$link`, or `$bytes` alongside other keys are kept as maps
#[must_use]
pub fn json_to_lex(json: &JsonValue) -> LexValue {
    // Lenient mode never errors — this unwrap is infallible by
    // construction (every `strict`-gated error path returns a plain
    // value instead in lenient mode).
    json_to_lex_with(json, LexParseOptions::default())
        .expect("json_to_lex in lenient mode is infallible")
}

/// Convert a JSON value to a `LexValue` with caller-supplied options.
///
/// In strict mode, returns [`JsonError`] for every TS-strict
/// violation; in lenient mode, falls back to plain maps / strings /
/// truncated integers (matching pre-0.2.2 behaviour).
pub fn json_to_lex_with(json: &JsonValue, opts: LexParseOptions) -> Result<LexValue, JsonError> {
    match json {
        JsonValue::Null => Ok(LexValue::Null),
        JsonValue::Bool(b) => Ok(LexValue::Bool(*b)),
        JsonValue::Number(n) => convert_number(n, opts),
        JsonValue::String(s) => Ok(LexValue::String(s.clone())),
        JsonValue::Array(arr) => {
            let items: Result<Vec<_>, _> = arr.iter().map(|v| json_to_lex_with(v, opts)).collect();
            Ok(LexValue::Array(items?))
        }
        JsonValue::Object(obj) => convert_object(obj, opts),
    }
}

/// Convert a JSON number honoring the strict safe-integer bound.
fn convert_number(n: &serde_json::Number, opts: LexParseOptions) -> Result<LexValue, JsonError> {
    if let Some(i) = n.as_i64() {
        if opts.strict && !(-JS_SAFE_INTEGER_MAX..=JS_SAFE_INTEGER_MAX).contains(&i) {
            return Err(JsonError::UnsafeInteger(n.to_string()));
        }
        return Ok(LexValue::Integer(i));
    }
    if let Some(f) = n.as_f64() {
        // Non-integer floats are data-model violations. In strict mode
        // we return an error; in lenient mode we truncate for back-
        // compat with pre-0.2.2 behaviour (which also truncated).
        //
        // NaN and infinity are never safe to coerce — even lenient
        // mode errors on them, since there's no meaningful integer
        // value to return.
        if f.is_nan() || f.is_infinite() {
            return Err(JsonError::UnsafeInteger(n.to_string()));
        }
        if f.fract() != 0.0 {
            if opts.strict {
                return Err(JsonError::UnsafeInteger(n.to_string()));
            }
            // Casting an out-of-range float to i64 is well-defined
            // in Rust: it saturates to MIN/MAX rather than panicking.
            return Ok(LexValue::Integer(f as i64));
        }
        // Whole-valued float. In strict mode, reject values outside
        // the i64 or the safe-integer range. In lenient mode, just
        // saturate — pre-0.2.2 callers got `LexValue::Integer(i64::MAX)`
        // for e.g. `4.4e99` rather than an error, and this preserves
        // that behaviour.
        if opts.strict {
            if f < i64::MIN as f64 || f > i64::MAX as f64 {
                return Err(JsonError::UnsafeInteger(n.to_string()));
            }
            let as_i = f as i64;
            if !(-JS_SAFE_INTEGER_MAX..=JS_SAFE_INTEGER_MAX).contains(&as_i) {
                return Err(JsonError::UnsafeInteger(n.to_string()));
            }
            return Ok(LexValue::Integer(as_i));
        }
        return Ok(LexValue::Integer(f as i64));
    }
    // u64 outside i64 range — serde_json accepts these. Strict mode
    // errors; lenient mode saturates at i64::MAX so `json_to_lex` can
    // honour its infallibility contract.
    if opts.strict {
        Err(JsonError::UnsafeInteger(n.to_string()))
    } else {
        Ok(LexValue::Integer(i64::MAX))
    }
}

/// Convert a JSON object, handling `$link` / `$bytes` single-key
/// wrappers and honouring the strict mode for malformed variants.
fn convert_object(
    obj: &serde_json::Map<String, JsonValue>,
    opts: LexParseOptions,
) -> Result<LexValue, JsonError> {
    // Single-key `$link` → CID
    if obj.len() == 1 {
        if let Some(link_val) = obj.get("$link") {
            return convert_link(link_val, opts);
        }
        if let Some(bytes_val) = obj.get("$bytes") {
            return convert_bytes(bytes_val, opts);
        }
    }

    // Regular object — convert recursively.
    let mut map = BTreeMap::new();
    for (key, value) in obj {
        if key == "__proto__" {
            if opts.strict {
                return Err(JsonError::ProtoPollution);
            }
            continue; // lenient: prevent prototype pollution silently
        }
        map.insert(key.clone(), json_to_lex_with(value, opts)?);
    }
    Ok(LexValue::Map(map))
}

/// Interpret a single-key `{"$link": x}` object.
fn convert_link(link_val: &JsonValue, opts: LexParseOptions) -> Result<LexValue, JsonError> {
    // $link MUST be a string.
    let s = if let JsonValue::String(s) = link_val {
        s
    } else {
        if opts.strict {
            return Err(JsonError::InvalidLink(format!(
                "expected string, got {}",
                json_shape(link_val),
            )));
        }
        // Lenient fallback: emit as plain map.
        return Ok(LexValue::Map(make_single_key_map("$link", link_val)));
    };

    if s.len() > MAX_LINK_LEN {
        if opts.strict {
            return Err(JsonError::InvalidLink(format!(
                "length {} exceeds max {MAX_LINK_LEN}",
                s.len(),
            )));
        }
        return Ok(LexValue::Map(make_single_key_map(
            "$link",
            &JsonValue::String(s.clone()),
        )));
    }

    match s.parse::<Cid>() {
        Ok(cid) => Ok(LexValue::Cid(cid)),
        Err(e) => {
            if opts.strict {
                return Err(JsonError::InvalidCid(e.to_string()));
            }
            Ok(LexValue::Map(make_single_key_map(
                "$link",
                &JsonValue::String(s.clone()),
            )))
        }
    }
}

/// Interpret a single-key `{"$bytes": x}` object.
fn convert_bytes(bytes_val: &JsonValue, opts: LexParseOptions) -> Result<LexValue, JsonError> {
    let s = if let JsonValue::String(s) = bytes_val {
        s
    } else {
        if opts.strict {
            return Err(JsonError::InvalidBytes(format!(
                "expected string, got {}",
                json_shape(bytes_val),
            )));
        }
        return Ok(LexValue::Map(make_single_key_map("$bytes", bytes_val)));
    };

    match BASE64_ENGINE.decode(s) {
        Ok(bytes) => Ok(LexValue::Bytes(bytes)),
        Err(e) => {
            if opts.strict {
                return Err(JsonError::InvalidBytes(e.to_string()));
            }
            Ok(LexValue::Map(make_single_key_map(
                "$bytes",
                &JsonValue::String(s.clone()),
            )))
        }
    }
}

/// One-key map helper for lenient-mode fallbacks.
fn make_single_key_map(key: &str, value: &JsonValue) -> BTreeMap<String, LexValue> {
    let mut map = BTreeMap::new();
    map.insert(key.to_string(), json_to_lex(value));
    map
}

/// Human-readable shape for error messages.
const fn json_shape(v: &JsonValue) -> &'static str {
    match v {
        JsonValue::Null => "null",
        JsonValue::Bool(_) => "boolean",
        JsonValue::Number(_) => "number",
        JsonValue::String(_) => "string",
        JsonValue::Array(_) => "array",
        JsonValue::Object(_) => "object",
    }
}

/// Convert a `LexValue` to a JSON value.
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
                let b64 = obj["$bytes"].as_str().unwrap();
                assert!(!b64.contains('='), "Should not have padding");
                let decoded_bytes = BASE64_ENGINE.decode(b64).unwrap();
                assert_eq!(decoded_bytes, data);
            }
            _ => panic!("Bytes should encode as object"),
        }

        let decoded = json_to_lex(&json);
        assert_eq!(decoded, lex);
    }

    #[test]
    fn link_with_extra_keys_stays_as_map() {
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
        let json_str = r#"{"$type": "blob", "ref": {"$link": "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity"}, "mimeType": "image/jpeg", "size": 10000}"#;
        let json: JsonValue = serde_json::from_str(json_str).unwrap();
        let lex = json_to_lex(&json);

        match &lex {
            LexValue::Map(map) => {
                assert_eq!(map.get("$type").unwrap().as_str(), Some("blob"));
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
        let json_str = r#"{"a":{"$link":"bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"},"b":{"$bytes":"nFERjvLLiw9qm45JrqH9QTzyC2Lu1Xb4ne6+sBrCzI0"},"c":{"$type":"blob","ref":{"$link":"bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity"},"mimeType":"image/jpeg","size":10000}}"#;

        let lex = lex_parse(json_str).unwrap();
        let back = lex_stringify(&lex);
        let lex2 = lex_parse(&back).unwrap();
        assert_eq!(lex, lex2);

        let map = lex.as_map().unwrap();
        assert!(map["a"].as_cid().is_some(), "a should be a CID");
        assert!(map["b"].as_bytes().is_some(), "b should be bytes");
        assert!(map["c"].as_map().is_some(), "c should be a map (blob ref)");
    }

    #[test]
    fn poorly_formatted_not_parsed_as_special() {
        let json_str = r#"{"a": "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"}"#;
        let lex = lex_parse(json_str).unwrap();
        let map = lex.as_map().unwrap();
        assert!(map["a"].as_str().is_some(), "Should be a string, not a CID");
    }

    // ── Strict-mode rejection tests ────────────────────────────────────

    #[test]
    fn strict_rejects_non_safe_integer() {
        let input = format!(r"{}", i64::MAX);
        let err = lex_parse_with(&input, LexParseOptions::strict()).unwrap_err();
        assert!(matches!(err, JsonError::UnsafeInteger(_)));

        // Lenient still accepts.
        let v = lex_parse(&input).unwrap();
        assert!(matches!(v, LexValue::Integer(_)));
    }

    #[test]
    fn strict_rejects_non_integer_float() {
        let input = "1.5";
        let err = lex_parse_with(input, LexParseOptions::strict()).unwrap_err();
        assert!(matches!(err, JsonError::UnsafeInteger(_)));

        let v = lex_parse(input).unwrap();
        assert_eq!(v, LexValue::Integer(1));
    }

    #[test]
    fn strict_rejects_malformed_link() {
        let input = r#"{"$link":"not-a-valid-cid"}"#;
        let err = lex_parse_with(input, LexParseOptions::strict()).unwrap_err();
        assert!(matches!(err, JsonError::InvalidCid(_)));

        // Lenient keeps as map.
        let v = lex_parse(input).unwrap();
        assert!(matches!(v, LexValue::Map(_)));
    }

    #[test]
    fn strict_rejects_link_exceeding_cap() {
        let long = "z".repeat(MAX_LINK_LEN + 1);
        let input = format!(r#"{{"$link":"{long}"}}"#);
        let err = lex_parse_with(&input, LexParseOptions::strict()).unwrap_err();
        assert!(
            matches!(&err, JsonError::InvalidLink(msg) if msg.contains("exceeds max")),
            "unexpected: {err:?}",
        );
    }

    #[test]
    fn strict_rejects_non_string_link() {
        let input = r#"{"$link":42}"#;
        let err = lex_parse_with(input, LexParseOptions::strict()).unwrap_err();
        assert!(matches!(err, JsonError::InvalidLink(_)));
    }

    #[test]
    fn strict_rejects_malformed_bytes() {
        let input = r#"{"$bytes":"!!!not valid base64!!!"}"#;
        let err = lex_parse_with(input, LexParseOptions::strict()).unwrap_err();
        assert!(matches!(err, JsonError::InvalidBytes(_)));

        // Lenient keeps as map.
        let v = lex_parse(input).unwrap();
        assert!(matches!(v, LexValue::Map(_)));
    }

    #[test]
    fn strict_rejects_proto_pollution() {
        let input = r#"{"__proto__":{"polluted":true}}"#;
        let err = lex_parse_with(input, LexParseOptions::strict()).unwrap_err();
        assert!(matches!(err, JsonError::ProtoPollution));

        // Lenient drops the key silently.
        let v = lex_parse(input).unwrap();
        let map = v.as_map().unwrap();
        assert!(!map.contains_key("__proto__"));
    }

    #[test]
    fn strict_accepts_canonical_input() {
        let cid = Cid::for_cbor(b"test");
        let mut m = BTreeMap::new();
        m.insert("cid".to_string(), LexValue::Cid(cid));
        m.insert("n".to_string(), LexValue::Integer(42));
        m.insert("b".to_string(), LexValue::Bytes(vec![1, 2, 3]));
        let val = LexValue::Map(m);

        let input = lex_stringify(&val);
        let parsed = lex_parse_with(&input, LexParseOptions::strict()).unwrap();
        assert_eq!(parsed, val);
    }

    #[test]
    fn lex_parse_json_bytes_entry_point() {
        let bytes = br#"{"x":1}"#;
        let v = lex_parse_json_bytes(bytes).unwrap();
        let map = v.as_map().unwrap();
        assert_eq!(map["x"], LexValue::Integer(1));
    }

    /// Regression: whole-valued floats outside the i64 range (e.g.
    /// `4.4e99`) and u64 values above `i64::MAX` previously returned
    /// `Err(UnsafeInteger(..))` even in lenient mode — which broke
    /// the "lenient is infallible" contract `json_to_lex` relies on
    /// (it `.expect()`s the result). Now saturates to `i64::MAX` in
    /// lenient mode. Found by the `lex_json_strict` fuzzer on input
    /// `4.444444444444444e+99`.
    #[test]
    fn lenient_saturates_oversized_floats_instead_of_erroring() {
        let huge = serde_json::from_str::<serde_json::Value>("4.444444444444444e+99").unwrap();
        // Direct — must not panic, must produce an integer.
        let lenient = json_to_lex(&huge);
        match lenient {
            LexValue::Integer(_) => {}
            other => panic!("expected Integer(saturated), got {other:?}"),
        }
        // And strict mode still errors (the spec-compliant behaviour
        // callers opt into).
        let strict_err = json_to_lex_with(&huge, LexParseOptions::strict());
        assert!(matches!(strict_err, Err(JsonError::UnsafeInteger(_))));
    }

    #[test]
    fn lenient_handles_u64_above_i64_max() {
        // u64::MAX serializes as a JSON number above i64::MAX. serde_json
        // decodes it as a u64; our lenient path must saturate rather
        // than error.
        let big = serde_json::from_str::<serde_json::Value>(&u64::MAX.to_string()).unwrap();
        let lenient = json_to_lex(&big);
        assert_eq!(lenient, LexValue::Integer(i64::MAX));
    }
}
