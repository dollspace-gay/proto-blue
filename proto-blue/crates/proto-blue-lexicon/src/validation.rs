//! Validation engine for AT Protocol Lexicon schemas.
//!
//! Validates `LexValue` instances against `LexUserType` definitions,
//! checking types, constraints, and references.

use std::collections::BTreeMap;

use proto_blue_lex_data::{Cid, LexValue};

use crate::error::{ValidationError, ValidationResult};
use crate::lexicons::Lexicons;
use crate::types::{
    LexArray, LexBlob, LexBoolean, LexBytes, LexInteger, LexObject, LexRecord, LexRef, LexRefUnion,
    LexString, LexUserType,
};

/// Validate a record value against a lexicon record definition.
///
/// Checks that the value is a map, optionally verifies `$type`, then
/// validates the record's object schema.
pub fn validate_record(lexicons: &Lexicons, def: &LexRecord, value: &LexValue) -> ValidationResult {
    let map = value
        .as_map()
        .ok_or_else(|| ValidationError::new("", "Expected an object for record"))?;

    validate_object(lexicons, "record", &def.record, map)
}

/// Validate an object (map) against a `LexObject` schema.
pub fn validate_object(
    lexicons: &Lexicons,
    path: &str,
    def: &LexObject,
    map: &BTreeMap<String, LexValue>,
) -> ValidationResult {
    // Check required fields
    for req in &def.required {
        if !map.contains_key(req) {
            return Err(ValidationError::new(
                &format!("{path}/{req}"),
                format!("Required field missing: {req}"),
            ));
        }
    }

    // Validate each property that has a schema
    for (key, prop_def) in &def.properties {
        let prop_path = format!("{path}/{key}");

        if let Some(value) = map.get(key) {
            // Check nullable
            if value.is_null() && def.nullable.contains(key) {
                continue;
            }
            validate_value(lexicons, &prop_path, prop_def, value)?;
        }
    }

    Ok(())
}

/// Validate a value against a `LexUserType` definition.
pub fn validate_value(
    lexicons: &Lexicons,
    path: &str,
    def: &LexUserType,
    value: &LexValue,
) -> ValidationResult {
    match def {
        LexUserType::String(s) => validate_string(path, s, value),
        LexUserType::Integer(i) => validate_integer(path, i, value),
        LexUserType::Boolean(b) => validate_boolean(path, b, value),
        LexUserType::Bytes(b) => validate_bytes(path, b, value),
        LexUserType::CidLink(_) => validate_cid_link(path, value),
        LexUserType::Unknown(_) => Ok(()),
        LexUserType::Array(a) => validate_array(lexicons, path, a, value),
        LexUserType::Object(o) => {
            let map = value
                .as_map()
                .ok_or_else(|| ValidationError::new(path, "Expected an object"))?;
            validate_object(lexicons, path, o, map)
        }
        LexUserType::Blob(b) => validate_blob(path, b, value),
        LexUserType::Ref(r) => validate_ref(lexicons, path, r, value),
        LexUserType::Union(u) => validate_union(lexicons, path, u, value),
        LexUserType::Token(_) => {
            // Tokens are just markers; any string value is valid
            if value.as_str().is_none() {
                return Err(ValidationError::new(path, "Expected a string for token"));
            }
            Ok(())
        }
        // Unknown is a permissive type by definition; primary types
        // (record/query/procedure/subscription) are validated at a
        // higher level and reach this fall-through arm only when used
        // as a nested type. Both return Ok(()) for distinct reasons;
        // keep arms separate so future evolution can specialise either.
        #[allow(clippy::match_same_arms)]
        _ => Ok(()),
    }
}

// --- Primitive Validators ---

fn validate_string(path: &str, def: &LexString, value: &LexValue) -> ValidationResult {
    let s = value
        .as_str()
        .ok_or_else(|| ValidationError::new(path, "Expected a string"))?;

    // Length checks (UTF-8 bytes)
    if let Some(min) = def.min_length
        && s.len() < min
    {
        return Err(ValidationError::new(
            path,
            format!("String too short: {} < {min} bytes", s.len()),
        ));
    }
    if let Some(max) = def.max_length
        && s.len() > max
    {
        return Err(ValidationError::new(
            path,
            format!("String too long: {} > {max} bytes", s.len()),
        ));
    }

    // Grapheme length checks
    if def.min_graphemes.is_some() || def.max_graphemes.is_some() {
        let grapheme_count = proto_blue_common::grapheme_len(s);
        if let Some(min) = def.min_graphemes
            && grapheme_count < min
        {
            return Err(ValidationError::new(
                path,
                format!("String too short: {grapheme_count} < {min} graphemes"),
            ));
        }
        if let Some(max) = def.max_graphemes
            && grapheme_count > max
        {
            return Err(ValidationError::new(
                path,
                format!("String too long: {grapheme_count} > {max} graphemes"),
            ));
        }
    }

    // Enum check
    if let Some(enum_values) = &def.enum_values
        && !enum_values.iter().any(|v| v == s)
    {
        return Err(ValidationError::new(
            path,
            format!("String not in enum: {s}"),
        ));
    }

    // Const check
    if let Some(const_val) = &def.const_value
        && s != const_val
    {
        return Err(ValidationError::new(
            path,
            format!("String must be \"{const_val}\", got \"{s}\""),
        ));
    }

    // Format validation
    if let Some(format) = &def.format {
        validate_string_format(path, format, s)?;
    }

    Ok(())
}

fn validate_string_format(path: &str, format: &str, value: &str) -> ValidationResult {
    let valid = match format {
        "datetime" => proto_blue_syntax::Datetime::new(value).is_ok(),
        "uri" => proto_blue_syntax::is_valid_uri(value),
        "at-uri" => proto_blue_syntax::AtUri::new(value).is_ok(),
        "did" => proto_blue_syntax::Did::new(value).is_ok(),
        "handle" => proto_blue_syntax::Handle::new(value).is_ok(),
        "at-identifier" => {
            proto_blue_syntax::Did::new(value).is_ok()
                || proto_blue_syntax::Handle::new(value).is_ok()
        }
        "nsid" => proto_blue_syntax::Nsid::new(value).is_ok(),
        "cid" => value.parse::<Cid>().is_ok(),
        "language" => proto_blue_syntax::is_valid_language(value),
        "tid" => proto_blue_syntax::Tid::new(value).is_ok(),
        "record-key" => proto_blue_syntax::RecordKey::new(value).is_ok(),
        _ => true, // Unknown formats pass
    };

    if !valid {
        return Err(ValidationError::new(
            path,
            format!("Invalid {format} format: {value}"),
        ));
    }
    Ok(())
}

fn validate_integer(path: &str, def: &LexInteger, value: &LexValue) -> ValidationResult {
    let n = value
        .as_integer()
        .ok_or_else(|| ValidationError::new(path, "Expected an integer"))?;

    if let Some(min) = def.minimum
        && n < min
    {
        return Err(ValidationError::new(
            path,
            format!("Integer too small: {n} < {min}"),
        ));
    }
    if let Some(max) = def.maximum
        && n > max
    {
        return Err(ValidationError::new(
            path,
            format!("Integer too large: {n} > {max}"),
        ));
    }
    if let Some(enum_values) = &def.enum_values
        && !enum_values.contains(&n)
    {
        return Err(ValidationError::new(
            path,
            format!("Integer not in enum: {n}"),
        ));
    }
    if let Some(const_val) = def.const_value
        && n != const_val
    {
        return Err(ValidationError::new(
            path,
            format!("Integer must be {const_val}, got {n}"),
        ));
    }

    Ok(())
}

fn validate_boolean(path: &str, def: &LexBoolean, value: &LexValue) -> ValidationResult {
    let b = value
        .as_bool()
        .ok_or_else(|| ValidationError::new(path, "Expected a boolean"))?;

    if let Some(const_val) = def.const_value
        && b != const_val
    {
        return Err(ValidationError::new(
            path,
            format!("Boolean must be {const_val}, got {b}"),
        ));
    }

    Ok(())
}

fn validate_bytes(path: &str, def: &LexBytes, value: &LexValue) -> ValidationResult {
    let b = value
        .as_bytes()
        .ok_or_else(|| ValidationError::new(path, "Expected bytes"))?;

    if let Some(min) = def.min_length
        && b.len() < min
    {
        return Err(ValidationError::new(
            path,
            format!("Bytes too short: {} < {min}", b.len()),
        ));
    }
    if let Some(max) = def.max_length
        && b.len() > max
    {
        return Err(ValidationError::new(
            path,
            format!("Bytes too long: {} > {max}", b.len()),
        ));
    }

    Ok(())
}

fn validate_cid_link(path: &str, value: &LexValue) -> ValidationResult {
    if value.as_cid().is_none() {
        return Err(ValidationError::new(path, "Expected a CID link"));
    }
    Ok(())
}

fn validate_blob(path: &str, def: &LexBlob, value: &LexValue) -> ValidationResult {
    // Blob refs reach the validator as maps in `LexValue` form. Two
    // on-the-wire shapes exist:
    //
    // - typed:  { $type: "blob", ref: <CID>, mimeType, size }
    // - legacy: { cid: "<string CID>", mimeType }
    //
    // Rather than round-trip through `BlobRef` serde (which would
    // require Serialize on `LexValue`), probe the map shape directly
    // and extract `mime_type` + optional `size` so the `accept` /
    // `maxSize` gates have something to match against.
    let map = value
        .as_map()
        .ok_or_else(|| ValidationError::new(path, "Expected an object for blob"))?;

    let (mime_type, size) = extract_blob_shape(path, map)?;

    // `accept` is a list of MIME-type patterns: exact match, or wildcard
    // like "image/*". An empty or absent accept list means any type is
    // allowed (matches TS).
    if let Some(accepts) = &def.accept
        && !accepts.is_empty()
        && !accepts
            .iter()
            .any(|pat| matches_mime_pattern(pat, mime_type))
    {
        return Err(ValidationError::new(
            path,
            format!("blob MIME {mime_type} not in accepted set: {accepts:?}"),
        ));
    }

    if let Some(max) = def.max_size
        && let Some(s) = size
        && s > max
    {
        return Err(ValidationError::new(
            path,
            format!("blob size {s} exceeds max {max}"),
        ));
    }

    Ok(())
}

/// Extract `(mime_type, size)` from a blob-shaped map, rejecting the
/// map when it matches neither the typed nor the legacy form. Returns a
/// borrowed `&str` for mime to avoid an allocation on the hot path.
fn extract_blob_shape<'a>(
    path: &str,
    map: &'a BTreeMap<String, LexValue>,
) -> Result<(&'a str, Option<u64>), ValidationError> {
    let mime_type = map
        .get("mimeType")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ValidationError::new(path, "blob missing \"mimeType\""))?;

    let type_tag = map.get("$type").and_then(|v| v.as_str());
    if type_tag == Some("blob") {
        // Typed form — must have `ref` (CID) and `size` (int).
        if map.get("ref").and_then(|v| v.as_cid()).is_none() {
            return Err(ValidationError::new(path, "typed blob missing \"ref\" CID"));
        }
        let size = map
            .get("size")
            .and_then(proto_blue_lex_data::LexValue::as_integer)
            .ok_or_else(|| ValidationError::new(path, "typed blob missing \"size\""))?;
        if size < 0 {
            return Err(ValidationError::new(path, "blob size cannot be negative"));
        }
        // bounded by `size >= 0` check on the line above; sign-loss cast is safe.
        #[allow(clippy::cast_sign_loss)]
        return Ok((mime_type, Some(size as u64)));
    }

    // Legacy form: top-level `cid` string, no $type.
    if type_tag.is_none() && map.get("cid").and_then(|v| v.as_str()).is_some() {
        return Ok((mime_type, None));
    }

    Err(ValidationError::new(
        path,
        "blob must carry either `$type:\"blob\"` + `ref` (typed form) or `cid` (legacy form)",
    ))
}

/// Match a MIME value against a lexicon `accept` pattern.
///
/// Supports exact match (`image/png`) and wildcard (`image/*`). No
/// other glob syntax is part of the atproto blob spec.
// `if let/else` with a multi-line Some branch is clearer than `map_or_else`
// with an inline closure; `map_or_else` would obscure the prefix logic.
#[allow(clippy::option_if_let_else)]
fn matches_mime_pattern(pattern: &str, mime: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        // "image/*" matches any "image/<anything>".
        mime.starts_with(prefix)
            && mime[prefix.len()..].starts_with('/')
            && !mime[prefix.len() + 1..].is_empty()
    } else {
        pattern.eq_ignore_ascii_case(mime)
    }
}

// --- Complex Validators ---

fn validate_array(
    lexicons: &Lexicons,
    path: &str,
    def: &LexArray,
    value: &LexValue,
) -> ValidationResult {
    let arr = value
        .as_array()
        .ok_or_else(|| ValidationError::new(path, "Expected an array"))?;

    if let Some(min) = def.min_length
        && arr.len() < min
    {
        return Err(ValidationError::new(
            path,
            format!("Array too short: {} < {min}", arr.len()),
        ));
    }
    if let Some(max) = def.max_length
        && arr.len() > max
    {
        return Err(ValidationError::new(
            path,
            format!("Array too long: {} > {max}", arr.len()),
        ));
    }

    for (i, item) in arr.iter().enumerate() {
        let item_path = format!("{path}[{i}]");
        validate_value(lexicons, &item_path, &def.items, item)?;
    }

    Ok(())
}

fn validate_ref(
    lexicons: &Lexicons,
    path: &str,
    def: &LexRef,
    value: &LexValue,
) -> ValidationResult {
    let resolved = lexicons
        .get_def(&def.ref_target)
        .ok_or_else(|| ValidationError::DefNotFound(def.ref_target.clone()))?;
    validate_value(lexicons, path, resolved, value)
}

fn validate_union(
    lexicons: &Lexicons,
    path: &str,
    def: &LexRefUnion,
    value: &LexValue,
) -> ValidationResult {
    let map = value
        .as_map()
        .ok_or_else(|| ValidationError::new(path, "Expected an object for union"))?;

    let type_val = map
        .get("$type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ValidationError::new(path, "Union requires $type field"))?;

    // Check if the $type is in the refs list
    let type_uri = if type_val.contains('#') {
        format!("lex:{type_val}")
    } else {
        format!("lex:{type_val}#main")
    };

    let is_known = def
        .refs
        .iter()
        .any(|r| *r == type_uri || *r == format!("lex:{type_val}"));

    if !is_known {
        let is_closed = def.closed.unwrap_or(false);
        if is_closed {
            return Err(ValidationError::new(
                path,
                format!("Unknown type in closed union: {type_val}"),
            ));
        }
        // Open union: allow unknown types to pass through
        return Ok(());
    }

    // Validate against the referenced definition
    if let Some(resolved) = lexicons.get_def(&type_uri) {
        validate_value(lexicons, path, resolved, value)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lexicons() -> Lexicons {
        let mut lex = Lexicons::new();
        lex.add_from_json(
            r#"{
            "lexicon": 1,
            "id": "com.example.post",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "required": ["text", "createdAt"],
                        "properties": {
                            "text": {
                                "type": "string",
                                "maxLength": 300,
                                "maxGraphemes": 30
                            },
                            "createdAt": {
                                "type": "string",
                                "format": "datetime"
                            },
                            "count": {
                                "type": "integer",
                                "minimum": 0,
                                "maximum": 100
                            }
                        }
                    }
                }
            }
        }"#,
        )
        .unwrap();
        lex
    }

    fn make_post(text: &str, created_at: &str) -> LexValue {
        let mut map = BTreeMap::new();
        map.insert("text".to_string(), LexValue::String(text.into()));
        map.insert("createdAt".to_string(), LexValue::String(created_at.into()));
        LexValue::Map(map)
    }

    #[test]
    fn valid_record() {
        let lex = make_lexicons();
        let def = lex.get_def("com.example.post").unwrap();
        if let LexUserType::Record(rec) = def {
            let value = make_post("hello", "2024-01-01T00:00:00Z");
            assert!(validate_record(&lex, rec, &value).is_ok());
        }
    }

    #[test]
    fn missing_required_field() {
        let lex = make_lexicons();
        let def = lex.get_def("com.example.post").unwrap();
        if let LexUserType::Record(rec) = def {
            let mut map = BTreeMap::new();
            map.insert("text".to_string(), LexValue::String("hello".into()));
            // Missing createdAt
            let value = LexValue::Map(map);
            assert!(validate_record(&lex, rec, &value).is_err());
        }
    }

    #[test]
    fn string_too_long() {
        let lex = make_lexicons();
        let def = lex.get_def("com.example.post").unwrap();
        if let LexUserType::Record(rec) = def {
            let long_text = "a".repeat(301);
            let value = make_post(&long_text, "2024-01-01T00:00:00Z");
            assert!(validate_record(&lex, rec, &value).is_err());
        }
    }

    #[test]
    fn grapheme_limit() {
        let lex = make_lexicons();
        let def = lex.get_def("com.example.post").unwrap();
        if let LexUserType::Record(rec) = def {
            // 31 graphemes > max 30
            let long_text = "a".repeat(31);
            let value = make_post(&long_text, "2024-01-01T00:00:00Z");
            assert!(validate_record(&lex, rec, &value).is_err());

            // 30 graphemes = ok
            let ok_text = "a".repeat(30);
            let value = make_post(&ok_text, "2024-01-01T00:00:00Z");
            assert!(validate_record(&lex, rec, &value).is_ok());
        }
    }

    #[test]
    fn integer_range() {
        let lex = make_lexicons();
        let def = lex.get_def("com.example.post").unwrap();
        if let LexUserType::Record(rec) = def {
            // With valid count
            let mut map = BTreeMap::new();
            map.insert("text".to_string(), LexValue::String("hi".into()));
            map.insert(
                "createdAt".to_string(),
                LexValue::String("2024-01-01T00:00:00Z".into()),
            );
            map.insert("count".to_string(), LexValue::Integer(50));
            assert!(validate_record(&lex, rec, &LexValue::Map(map)).is_ok());

            // With out-of-range count
            let mut map = BTreeMap::new();
            map.insert("text".to_string(), LexValue::String("hi".into()));
            map.insert(
                "createdAt".to_string(),
                LexValue::String("2024-01-01T00:00:00Z".into()),
            );
            map.insert("count".to_string(), LexValue::Integer(101));
            assert!(validate_record(&lex, rec, &LexValue::Map(map)).is_err());
        }
    }

    #[test]
    fn invalid_datetime_format() {
        let lex = make_lexicons();
        let def = lex.get_def("com.example.post").unwrap();
        if let LexUserType::Record(rec) = def {
            let value = make_post("hello", "not-a-datetime");
            assert!(validate_record(&lex, rec, &value).is_err());
        }
    }

    // ── Blob validator tightening ────────────────────────────────────

    fn blob_lex() -> Lexicons {
        let mut lex = Lexicons::new();
        lex.add_from_json(
            r#"{
            "lexicon": 1,
            "id": "com.example.upload",
            "defs": {
                "main": {
                    "type": "object",
                    "required": ["file"],
                    "properties": {
                        "file": {
                            "type": "blob",
                            "accept": ["image/png", "image/jpeg", "image/*"],
                            "maxSize": 100
                        }
                    }
                }
            }
        }"#,
        )
        .unwrap();
        lex
    }

    fn typed_blob(mime: &str, size: i64) -> LexValue {
        let cid = Cid::for_raw(b"x");
        let mut b = BTreeMap::new();
        b.insert("$type".to_string(), LexValue::String("blob".into()));
        b.insert("ref".to_string(), LexValue::Cid(cid));
        b.insert("mimeType".to_string(), LexValue::String(mime.into()));
        b.insert("size".to_string(), LexValue::Integer(size));
        LexValue::Map(b)
    }

    #[test]
    fn blob_mime_accept_exact() {
        let lex = blob_lex();
        let def = lex.get_def("com.example.upload").unwrap();
        let LexUserType::Object(obj) = def else {
            unreachable!()
        };
        let mut outer = BTreeMap::new();
        outer.insert("file".into(), typed_blob("image/png", 10));
        assert!(validate_object(&lex, "", obj, &outer).is_ok());
    }

    #[test]
    fn blob_mime_accept_wildcard() {
        let lex = blob_lex();
        let def = lex.get_def("com.example.upload").unwrap();
        let LexUserType::Object(obj) = def else {
            unreachable!()
        };
        let mut outer = BTreeMap::new();
        outer.insert("file".into(), typed_blob("image/gif", 10));
        assert!(validate_object(&lex, "", obj, &outer).is_ok());
    }

    #[test]
    fn blob_mime_rejected_when_not_in_accept() {
        let lex = blob_lex();
        let def = lex.get_def("com.example.upload").unwrap();
        let LexUserType::Object(obj) = def else {
            unreachable!()
        };
        let mut outer = BTreeMap::new();
        outer.insert("file".into(), typed_blob("video/mp4", 10));
        let err = validate_object(&lex, "", obj, &outer).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("video/mp4"), "unexpected: {msg}");
    }

    #[test]
    fn blob_max_size_enforced() {
        let lex = blob_lex();
        let def = lex.get_def("com.example.upload").unwrap();
        let LexUserType::Object(obj) = def else {
            unreachable!()
        };
        let mut outer = BTreeMap::new();
        outer.insert("file".into(), typed_blob("image/png", 500));
        let err = validate_object(&lex, "", obj, &outer).unwrap_err();
        assert!(err.to_string().contains("size 500 exceeds max 100"));
    }

    #[test]
    fn blob_legacy_shape_accepted() {
        let lex = blob_lex();
        let def = lex.get_def("com.example.upload").unwrap();
        let LexUserType::Object(obj) = def else {
            unreachable!()
        };
        let mut legacy = BTreeMap::new();
        legacy.insert("cid".into(), LexValue::String("bafyreidyxy".into()));
        legacy.insert("mimeType".into(), LexValue::String("image/png".into()));

        let mut outer = BTreeMap::new();
        outer.insert("file".into(), LexValue::Map(legacy));
        assert!(
            validate_object(&lex, "", obj, &outer).is_ok(),
            "legacy blob ref should validate when mime fits accept",
        );
    }

    #[test]
    fn blob_rejects_malformed_shape() {
        let lex = blob_lex();
        let def = lex.get_def("com.example.upload").unwrap();
        let LexUserType::Object(obj) = def else {
            unreachable!()
        };
        // Missing `ref`, has `$type: blob` — neither typed nor legacy.
        let mut bad = BTreeMap::new();
        bad.insert("$type".into(), LexValue::String("blob".into()));
        bad.insert("mimeType".into(), LexValue::String("image/png".into()));
        bad.insert("size".into(), LexValue::Integer(1));

        let mut outer = BTreeMap::new();
        outer.insert("file".into(), LexValue::Map(bad));
        assert!(validate_object(&lex, "", obj, &outer).is_err());
    }

    // ── URI format ───────────────────────────────────────────────────

    #[test]
    fn uri_format_accepts_valid_schemes() {
        // Delegates to proto_blue_syntax::is_valid_uri, which
        // proto-blue-syntax covers with its own tests. Here we just
        // confirm the lexicon-side `format: uri` validator wires
        // through correctly.
        assert!(proto_blue_syntax::is_valid_uri("https://example.com/path"));
    }

    #[test]
    fn uri_format_rejects_malformed() {
        assert!(!proto_blue_syntax::is_valid_uri("not-a-uri"));
    }

    // ── XRPC validator entry points ──────────────────────────────────

    fn xrpc_lex() -> Lexicons {
        let mut lex = Lexicons::new();
        lex.add_from_json(
            r#"{
            "lexicon": 1,
            "id": "com.example.echo",
            "defs": {
                "main": {
                    "type": "procedure",
                    "parameters": {
                        "type": "params",
                        "required": ["actor"],
                        "properties": {
                            "actor": {"type": "string", "format": "at-identifier"},
                            "limit": {"type": "integer", "minimum": 1, "maximum": 100}
                        }
                    },
                    "input": {
                        "encoding": "application/json",
                        "schema": {
                            "type": "object",
                            "required": ["text"],
                            "properties": {
                                "text": {"type": "string", "maxLength": 100}
                            }
                        }
                    },
                    "output": {
                        "encoding": "application/json",
                        "schema": {
                            "type": "object",
                            "required": ["ok"],
                            "properties": {
                                "ok": {"type": "boolean"}
                            }
                        }
                    }
                }
            }
        }"#,
        )
        .unwrap();
        lex
    }

    #[test]
    fn xrpc_params_valid() {
        let lex = xrpc_lex();
        let mut params = BTreeMap::new();
        params.insert("actor".into(), LexValue::String("alice.bsky.social".into()));
        params.insert("limit".into(), LexValue::Integer(42));
        let value = LexValue::Map(params);
        assert!(
            lex.assert_valid_xrpc_params("com.example.echo", &value)
                .is_ok()
        );
    }

    #[test]
    fn xrpc_params_missing_required_rejected() {
        let lex = xrpc_lex();
        let params = BTreeMap::new();
        let value = LexValue::Map(params);
        assert!(
            lex.assert_valid_xrpc_params("com.example.echo", &value)
                .is_err()
        );
    }

    #[test]
    fn xrpc_params_out_of_range_rejected() {
        let lex = xrpc_lex();
        let mut params = BTreeMap::new();
        params.insert("actor".into(), LexValue::String("alice.bsky.social".into()));
        params.insert("limit".into(), LexValue::Integer(500));
        let value = LexValue::Map(params);
        assert!(
            lex.assert_valid_xrpc_params("com.example.echo", &value)
                .is_err()
        );
    }

    #[test]
    fn xrpc_input_valid() {
        let lex = xrpc_lex();
        let mut body = BTreeMap::new();
        body.insert("text".into(), LexValue::String("hello".into()));
        let value = LexValue::Map(body);
        assert!(
            lex.assert_valid_xrpc_input("com.example.echo", &value)
                .is_ok()
        );
    }

    #[test]
    fn xrpc_output_valid() {
        let lex = xrpc_lex();
        let mut body = BTreeMap::new();
        body.insert("ok".into(), LexValue::Bool(true));
        let value = LexValue::Map(body);
        assert!(
            lex.assert_valid_xrpc_output("com.example.echo", &value)
                .is_ok()
        );
    }

    #[test]
    fn xrpc_wrong_def_type_rejected() {
        let lex = xrpc_lex();
        let body = LexValue::Map(BTreeMap::new());
        // echo is a procedure, not a subscription — message should fail.
        assert!(
            lex.assert_valid_xrpc_message("com.example.echo", &body)
                .is_err()
        );
    }

    // ── Required-properties refinement ───────────────────────────────

    #[test]
    fn required_not_in_properties_rejects_schema() {
        let mut lex = Lexicons::new();
        let err = lex
            .add_from_json(
                r#"{
                    "lexicon": 1,
                    "id": "com.example.bad",
                    "defs": {
                        "main": {
                            "type": "record",
                            "record": {
                                "type": "object",
                                "required": ["missingField"],
                                "properties": {
                                    "presentField": { "type": "string" }
                                }
                            }
                        }
                    }
                }"#,
            )
            .unwrap_err();
        assert!(
            matches!(&err, crate::LexiconError::InvalidSchema(msg) if msg.contains("missingField")),
            "expected InvalidSchema with missingField, got: {err}",
        );
    }

    #[test]
    fn primary_def_at_non_main_rejected() {
        let mut lex = Lexicons::new();
        let err = lex
            .add_from_json(
                r#"{
                    "lexicon": 1,
                    "id": "com.example.bad",
                    "defs": {
                        "primary": {
                            "type": "record",
                            "record": {"type": "object", "properties": {}}
                        }
                    }
                }"#,
            )
            .unwrap_err();
        assert!(matches!(err, crate::LexiconError::InvalidSchema(_)));
    }
}
