//! Validation engine for AT Protocol Lexicon schemas.
//!
//! Validates `LexValue` instances against `LexUserType` definitions,
//! checking types, constraints, and references.

use std::collections::BTreeMap;

use proto_blue_lex_data::{Cid, LexValue};

use crate::error::{ValidationError, ValidationResult};
use crate::lexicons::Lexicons;
use crate::types::*;

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

/// Validate an object (map) against a LexObject schema.
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

/// Validate a value against a LexUserType definition.
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
        LexUserType::Blob(_) => validate_blob(path, value),
        LexUserType::Ref(r) => validate_ref(lexicons, path, r, value),
        LexUserType::Union(u) => validate_union(lexicons, path, u, value),
        LexUserType::Token(_) => {
            // Tokens are just markers; any string value is valid
            if value.as_str().is_none() {
                return Err(ValidationError::new(path, "Expected a string for token"));
            }
            Ok(())
        }
        _ => Ok(()), // Primary types are validated at a higher level
    }
}

// --- Primitive Validators ---

fn validate_string(path: &str, def: &LexString, value: &LexValue) -> ValidationResult {
    let s = value
        .as_str()
        .ok_or_else(|| ValidationError::new(path, "Expected a string"))?;

    // Length checks (UTF-8 bytes)
    if let Some(min) = def.min_length {
        if s.len() < min {
            return Err(ValidationError::new(
                path,
                format!("String too short: {} < {min} bytes", s.len()),
            ));
        }
    }
    if let Some(max) = def.max_length {
        if s.len() > max {
            return Err(ValidationError::new(
                path,
                format!("String too long: {} > {max} bytes", s.len()),
            ));
        }
    }

    // Grapheme length checks
    if def.min_graphemes.is_some() || def.max_graphemes.is_some() {
        let grapheme_count = proto_blue_common::grapheme_len(s);
        if let Some(min) = def.min_graphemes {
            if grapheme_count < min {
                return Err(ValidationError::new(
                    path,
                    format!("String too short: {grapheme_count} < {min} graphemes"),
                ));
            }
        }
        if let Some(max) = def.max_graphemes {
            if grapheme_count > max {
                return Err(ValidationError::new(
                    path,
                    format!("String too long: {grapheme_count} > {max} graphemes"),
                ));
            }
        }
    }

    // Enum check
    if let Some(enum_values) = &def.enum_values {
        if !enum_values.iter().any(|v| v == s) {
            return Err(ValidationError::new(
                path,
                format!("String not in enum: {s}"),
            ));
        }
    }

    // Const check
    if let Some(const_val) = &def.const_value {
        if s != const_val {
            return Err(ValidationError::new(
                path,
                format!("String must be \"{const_val}\", got \"{s}\""),
            ));
        }
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
        "uri" => value.contains(':'), // Basic URI check
        "at-uri" => proto_blue_syntax::AtUri::new(value).is_ok(),
        "did" => proto_blue_syntax::Did::new(value).is_ok(),
        "handle" => proto_blue_syntax::Handle::new(value).is_ok(),
        "at-identifier" => {
            proto_blue_syntax::Did::new(value).is_ok() || proto_blue_syntax::Handle::new(value).is_ok()
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

    if let Some(min) = def.minimum {
        if n < min {
            return Err(ValidationError::new(
                path,
                format!("Integer too small: {n} < {min}"),
            ));
        }
    }
    if let Some(max) = def.maximum {
        if n > max {
            return Err(ValidationError::new(
                path,
                format!("Integer too large: {n} > {max}"),
            ));
        }
    }
    if let Some(enum_values) = &def.enum_values {
        if !enum_values.contains(&n) {
            return Err(ValidationError::new(
                path,
                format!("Integer not in enum: {n}"),
            ));
        }
    }
    if let Some(const_val) = def.const_value {
        if n != const_val {
            return Err(ValidationError::new(
                path,
                format!("Integer must be {const_val}, got {n}"),
            ));
        }
    }

    Ok(())
}

fn validate_boolean(path: &str, def: &LexBoolean, value: &LexValue) -> ValidationResult {
    let b = value
        .as_bool()
        .ok_or_else(|| ValidationError::new(path, "Expected a boolean"))?;

    if let Some(const_val) = def.const_value {
        if b != const_val {
            return Err(ValidationError::new(
                path,
                format!("Boolean must be {const_val}, got {b}"),
            ));
        }
    }

    Ok(())
}

fn validate_bytes(path: &str, def: &LexBytes, value: &LexValue) -> ValidationResult {
    let b = value
        .as_bytes()
        .ok_or_else(|| ValidationError::new(path, "Expected bytes"))?;

    if let Some(min) = def.min_length {
        if b.len() < min {
            return Err(ValidationError::new(
                path,
                format!("Bytes too short: {} < {min}", b.len()),
            ));
        }
    }
    if let Some(max) = def.max_length {
        if b.len() > max {
            return Err(ValidationError::new(
                path,
                format!("Bytes too long: {} > {max}", b.len()),
            ));
        }
    }

    Ok(())
}

fn validate_cid_link(path: &str, value: &LexValue) -> ValidationResult {
    if value.as_cid().is_none() {
        return Err(ValidationError::new(path, "Expected a CID link"));
    }
    Ok(())
}

fn validate_blob(path: &str, value: &LexValue) -> ValidationResult {
    // Blob refs are maps with $type: "blob"
    let map = value
        .as_map()
        .ok_or_else(|| ValidationError::new(path, "Expected an object for blob"))?;

    match map.get("$type").and_then(|v| v.as_str()) {
        Some("blob") => Ok(()),
        _ => Err(ValidationError::new(
            path,
            "Expected blob object with $type: \"blob\"",
        )),
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

    if let Some(min) = def.min_length {
        if arr.len() < min {
            return Err(ValidationError::new(
                path,
                format!("Array too short: {} < {min}", arr.len()),
            ));
        }
    }
    if let Some(max) = def.max_length {
        if arr.len() > max {
            return Err(ValidationError::new(
                path,
                format!("Array too long: {} > {max}", arr.len()),
            ));
        }
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
            r##"{
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
        }"##,
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
}
