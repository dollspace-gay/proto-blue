//! Lexicon schema type definitions.
//!
//! These types represent the Lexicon schema language used to define
//! AT Protocol APIs. They can be deserialized from the JSON lexicon
//! files found in the `lexicons/` directory.

use std::collections::HashMap;

use serde::Deserialize;

/// A Lexicon document — the top-level schema file.
#[derive(Debug, Clone, Deserialize)]
pub struct LexiconDoc {
    /// Lexicon version (always 1).
    pub lexicon: u32,
    /// The NSID identifier for this lexicon (e.g., "app.bsky.feed.post").
    pub id: String,
    /// Optional revision number.
    #[serde(default)]
    pub revision: Option<u32>,
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Definitions within this lexicon. The "main" key is the primary definition.
    pub defs: HashMap<String, LexUserType>,
}

/// A user-defined type in the Lexicon schema.
///
/// This is the discriminated union of all possible definition types,
/// tagged by the `type` field in JSON.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum LexUserType {
    // Primary definition types (only allowed at "main")
    #[serde(rename = "record")]
    Record(LexRecord),
    #[serde(rename = "query")]
    Query(LexXrpcQuery),
    #[serde(rename = "procedure")]
    Procedure(LexXrpcProcedure),
    #[serde(rename = "subscription")]
    Subscription(LexXrpcSubscription),

    // Data types
    #[serde(rename = "object")]
    Object(LexObject),
    #[serde(rename = "array")]
    Array(LexArray),
    #[serde(rename = "string")]
    String(LexString),
    #[serde(rename = "integer")]
    Integer(LexInteger),
    #[serde(rename = "boolean")]
    Boolean(LexBoolean),
    #[serde(rename = "bytes")]
    Bytes(LexBytes),
    #[serde(rename = "cid-link", alias = "cidLink")]
    CidLink(LexCidLink),
    #[serde(rename = "blob")]
    Blob(LexBlob),
    #[serde(rename = "token")]
    Token(LexToken),
    #[serde(rename = "unknown")]
    Unknown(LexUnknown),

    // Reference types
    #[serde(rename = "ref")]
    Ref(LexRef),
    #[serde(rename = "union")]
    Union(LexRefUnion),

    // Parameter types
    #[serde(rename = "params")]
    Params(LexXrpcParameters),

    // Permission types
    #[serde(rename = "permission")]
    Permission(LexPermission),
    #[serde(rename = "permission-set")]
    PermissionSet(LexPermissionSet),
}

impl LexUserType {
    /// Check if this is a primary type (record/query/procedure/subscription).
    pub fn is_primary(&self) -> bool {
        matches!(
            self,
            LexUserType::Record(_)
                | LexUserType::Query(_)
                | LexUserType::Procedure(_)
                | LexUserType::Subscription(_)
        )
    }

    /// Get the type name string.
    pub fn type_name(&self) -> &'static str {
        match self {
            LexUserType::Record(_) => "record",
            LexUserType::Query(_) => "query",
            LexUserType::Procedure(_) => "procedure",
            LexUserType::Subscription(_) => "subscription",
            LexUserType::Object(_) => "object",
            LexUserType::Array(_) => "array",
            LexUserType::String(_) => "string",
            LexUserType::Integer(_) => "integer",
            LexUserType::Boolean(_) => "boolean",
            LexUserType::Bytes(_) => "bytes",
            LexUserType::CidLink(_) => "cid-link",
            LexUserType::Blob(_) => "blob",
            LexUserType::Token(_) => "token",
            LexUserType::Unknown(_) => "unknown",
            LexUserType::Ref(_) => "ref",
            LexUserType::Union(_) => "union",
            LexUserType::Params(_) => "params",
            LexUserType::Permission(_) => "permission",
            LexUserType::PermissionSet(_) => "permission-set",
        }
    }
}

// --- Record ---

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexRecord {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    pub record: LexObject,
}

// --- XRPC Types ---

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexXrpcQuery {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub parameters: Option<LexXrpcParameters>,
    #[serde(default)]
    pub output: Option<LexXrpcBody>,
    #[serde(default)]
    pub errors: Vec<LexXrpcError>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexXrpcProcedure {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub parameters: Option<LexXrpcParameters>,
    #[serde(default)]
    pub input: Option<LexXrpcBody>,
    #[serde(default)]
    pub output: Option<LexXrpcBody>,
    #[serde(default)]
    pub errors: Vec<LexXrpcError>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexXrpcSubscription {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub parameters: Option<LexXrpcParameters>,
    #[serde(default)]
    pub message: Option<LexXrpcBody>,
    #[serde(default)]
    pub errors: Vec<LexXrpcError>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexXrpcParameters {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub properties: HashMap<String, LexUserType>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexXrpcBody {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub encoding: Option<String>,
    #[serde(default)]
    pub schema: Option<Box<LexUserType>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexXrpcError {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

// --- Data Types ---

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexObject {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub nullable: Vec<String>,
    #[serde(default)]
    pub properties: HashMap<String, LexUserType>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexArray {
    #[serde(default)]
    pub description: Option<String>,
    pub items: Box<LexUserType>,
    #[serde(default)]
    pub min_length: Option<usize>,
    #[serde(default)]
    pub max_length: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexString {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub min_length: Option<usize>,
    #[serde(default)]
    pub max_length: Option<usize>,
    #[serde(default)]
    pub min_graphemes: Option<usize>,
    #[serde(default)]
    pub max_graphemes: Option<usize>,
    #[serde(default, rename = "enum")]
    pub enum_values: Option<Vec<String>>,
    #[serde(default, rename = "const")]
    pub const_value: Option<String>,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub known_values: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexInteger {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub minimum: Option<i64>,
    #[serde(default)]
    pub maximum: Option<i64>,
    #[serde(default, rename = "enum")]
    pub enum_values: Option<Vec<i64>>,
    #[serde(default, rename = "const")]
    pub const_value: Option<i64>,
    #[serde(default)]
    pub default: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexBoolean {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub default: Option<bool>,
    #[serde(default, rename = "const")]
    pub const_value: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexBytes {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub min_length: Option<usize>,
    #[serde(default)]
    pub max_length: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexCidLink {
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexBlob {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub accept: Option<Vec<String>>,
    #[serde(default)]
    pub max_size: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexToken {
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexUnknown {
    #[serde(default)]
    pub description: Option<String>,
}

// --- Reference Types ---

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexRef {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "ref")]
    pub ref_target: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexRefUnion {
    #[serde(default)]
    pub description: Option<String>,
    pub refs: Vec<String>,
    #[serde(default)]
    pub closed: Option<bool>,
}

// --- Permission Types ---

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexPermission {
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LexPermissionSet {
    #[serde(default)]
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- is_primary tests ---

    #[test]
    fn is_primary_true_for_record() {
        let val: LexUserType = serde_json::from_value(
            json!({"type": "record", "record": {"type": "object", "properties": {}}}),
        )
        .unwrap();
        assert!(val.is_primary());
    }

    #[test]
    fn is_primary_true_for_query() {
        let val: LexUserType = serde_json::from_value(json!({"type": "query"})).unwrap();
        assert!(val.is_primary());
    }

    #[test]
    fn is_primary_true_for_procedure() {
        let val: LexUserType = serde_json::from_value(json!({"type": "procedure"})).unwrap();
        assert!(val.is_primary());
    }

    #[test]
    fn is_primary_true_for_subscription() {
        let val: LexUserType = serde_json::from_value(json!({"type": "subscription"})).unwrap();
        assert!(val.is_primary());
    }

    #[test]
    fn is_primary_false_for_object() {
        let val: LexUserType =
            serde_json::from_value(json!({"type": "object", "properties": {}})).unwrap();
        assert!(!val.is_primary());
    }

    #[test]
    fn is_primary_false_for_string() {
        let val: LexUserType = serde_json::from_value(json!({"type": "string"})).unwrap();
        assert!(!val.is_primary());
    }

    #[test]
    fn is_primary_false_for_integer() {
        let val: LexUserType = serde_json::from_value(json!({"type": "integer"})).unwrap();
        assert!(!val.is_primary());
    }

    #[test]
    fn is_primary_false_for_boolean() {
        let val: LexUserType = serde_json::from_value(json!({"type": "boolean"})).unwrap();
        assert!(!val.is_primary());
    }

    #[test]
    fn is_primary_false_for_ref() {
        let val: LexUserType =
            serde_json::from_value(json!({"type": "ref", "ref": "com.example.thing"})).unwrap();
        assert!(!val.is_primary());
    }

    #[test]
    fn is_primary_false_for_union() {
        let val: LexUserType =
            serde_json::from_value(json!({"type": "union", "refs": ["com.example.a"]})).unwrap();
        assert!(!val.is_primary());
    }

    #[test]
    fn is_primary_false_for_blob() {
        let val: LexUserType = serde_json::from_value(json!({"type": "blob"})).unwrap();
        assert!(!val.is_primary());
    }

    #[test]
    fn is_primary_false_for_array() {
        let val: LexUserType =
            serde_json::from_value(json!({"type": "array", "items": {"type": "string"}})).unwrap();
        assert!(!val.is_primary());
    }

    // --- type_name tests ---

    #[test]
    fn type_name_record() {
        let val: LexUserType = serde_json::from_value(
            json!({"type": "record", "record": {"type": "object", "properties": {}}}),
        )
        .unwrap();
        assert_eq!(val.type_name(), "record");
    }

    #[test]
    fn type_name_query() {
        let val: LexUserType = serde_json::from_value(json!({"type": "query"})).unwrap();
        assert_eq!(val.type_name(), "query");
    }

    #[test]
    fn type_name_procedure() {
        let val: LexUserType = serde_json::from_value(json!({"type": "procedure"})).unwrap();
        assert_eq!(val.type_name(), "procedure");
    }

    #[test]
    fn type_name_subscription() {
        let val: LexUserType = serde_json::from_value(json!({"type": "subscription"})).unwrap();
        assert_eq!(val.type_name(), "subscription");
    }

    #[test]
    fn type_name_object() {
        let val: LexUserType =
            serde_json::from_value(json!({"type": "object", "properties": {}})).unwrap();
        assert_eq!(val.type_name(), "object");
    }

    #[test]
    fn type_name_array() {
        let val: LexUserType =
            serde_json::from_value(json!({"type": "array", "items": {"type": "string"}})).unwrap();
        assert_eq!(val.type_name(), "array");
    }

    #[test]
    fn type_name_string() {
        let val: LexUserType = serde_json::from_value(json!({"type": "string"})).unwrap();
        assert_eq!(val.type_name(), "string");
    }

    #[test]
    fn type_name_integer() {
        let val: LexUserType = serde_json::from_value(json!({"type": "integer"})).unwrap();
        assert_eq!(val.type_name(), "integer");
    }

    #[test]
    fn type_name_boolean() {
        let val: LexUserType = serde_json::from_value(json!({"type": "boolean"})).unwrap();
        assert_eq!(val.type_name(), "boolean");
    }

    #[test]
    fn type_name_bytes() {
        let val: LexUserType = serde_json::from_value(json!({"type": "bytes"})).unwrap();
        assert_eq!(val.type_name(), "bytes");
    }

    #[test]
    fn type_name_cid_link() {
        let val: LexUserType = serde_json::from_value(json!({"type": "cid-link"})).unwrap();
        assert_eq!(val.type_name(), "cid-link");
    }

    #[test]
    fn type_name_blob() {
        let val: LexUserType = serde_json::from_value(json!({"type": "blob"})).unwrap();
        assert_eq!(val.type_name(), "blob");
    }

    #[test]
    fn type_name_token() {
        let val: LexUserType = serde_json::from_value(json!({"type": "token"})).unwrap();
        assert_eq!(val.type_name(), "token");
    }

    #[test]
    fn type_name_unknown() {
        let val: LexUserType = serde_json::from_value(json!({"type": "unknown"})).unwrap();
        assert_eq!(val.type_name(), "unknown");
    }

    #[test]
    fn type_name_ref() {
        let val: LexUserType =
            serde_json::from_value(json!({"type": "ref", "ref": "com.example.foo"})).unwrap();
        assert_eq!(val.type_name(), "ref");
    }

    #[test]
    fn type_name_union() {
        let val: LexUserType =
            serde_json::from_value(json!({"type": "union", "refs": ["com.example.a"]})).unwrap();
        assert_eq!(val.type_name(), "union");
    }

    #[test]
    fn type_name_params() {
        let val: LexUserType = serde_json::from_value(json!({"type": "params"})).unwrap();
        assert_eq!(val.type_name(), "params");
    }

    #[test]
    fn type_name_permission() {
        let val: LexUserType = serde_json::from_value(json!({"type": "permission"})).unwrap();
        assert_eq!(val.type_name(), "permission");
    }

    #[test]
    fn type_name_permission_set() {
        let val: LexUserType = serde_json::from_value(json!({"type": "permission-set"})).unwrap();
        assert_eq!(val.type_name(), "permission-set");
    }

    // --- LexiconDoc deserialization ---

    #[test]
    fn deserialize_minimal_lexicon_doc() {
        let doc: LexiconDoc = serde_json::from_value(json!({
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "query"
                }
            }
        }))
        .unwrap();
        assert_eq!(doc.lexicon, 1);
        assert_eq!(doc.id, "com.example.test");
        assert!(doc.revision.is_none());
        assert!(doc.description.is_none());
        assert!(doc.defs.contains_key("main"));
        assert!(doc.defs["main"].is_primary());
    }

    #[test]
    fn deserialize_lexicon_doc_with_optional_fields() {
        let doc: LexiconDoc = serde_json::from_value(json!({
            "lexicon": 1,
            "id": "app.bsky.feed.post",
            "revision": 2,
            "description": "A feed post record.",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "required": ["text"],
                        "properties": {
                            "text": { "type": "string", "maxLength": 300 }
                        }
                    }
                }
            }
        }))
        .unwrap();
        assert_eq!(doc.revision, Some(2));
        assert_eq!(doc.description.as_deref(), Some("A feed post record."));
        assert_eq!(doc.defs["main"].type_name(), "record");
    }

    // --- LexUserType variant deserialization ---

    #[test]
    fn deserialize_record_variant() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "record",
            "description": "A post",
            "key": "tid",
            "record": {
                "type": "object",
                "required": ["text"],
                "properties": {
                    "text": { "type": "string" }
                }
            }
        }))
        .unwrap();
        assert_eq!(val.type_name(), "record");
        if let LexUserType::Record(r) = &val {
            assert_eq!(r.description.as_deref(), Some("A post"));
            assert_eq!(r.key.as_deref(), Some("tid"));
            assert_eq!(r.record.required, vec!["text"]);
            assert!(r.record.properties.contains_key("text"));
        } else {
            panic!("Expected Record variant");
        }
    }

    #[test]
    fn deserialize_query_variant() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "query",
            "description": "Fetch a thing",
            "parameters": {
                "type": "params",
                "required": ["id"],
                "properties": {
                    "id": { "type": "string" }
                }
            },
            "output": {
                "encoding": "application/json",
                "schema": { "type": "object", "properties": {} }
            },
            "errors": [
                { "name": "NotFound", "description": "Thing not found" }
            ]
        }))
        .unwrap();
        if let LexUserType::Query(q) = &val {
            assert_eq!(q.description.as_deref(), Some("Fetch a thing"));
            assert!(q.parameters.is_some());
            let params = q.parameters.as_ref().unwrap();
            assert_eq!(params.required, vec!["id"]);
            assert!(q.output.is_some());
            assert_eq!(q.errors.len(), 1);
            assert_eq!(q.errors[0].name, "NotFound");
        } else {
            panic!("Expected Query variant");
        }
    }

    #[test]
    fn deserialize_procedure_variant() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "procedure",
            "description": "Create something",
            "input": {
                "encoding": "application/json",
                "schema": { "type": "object", "properties": {} }
            },
            "output": {
                "encoding": "application/json",
                "schema": { "type": "object", "properties": {} }
            }
        }))
        .unwrap();
        if let LexUserType::Procedure(p) = &val {
            assert_eq!(p.description.as_deref(), Some("Create something"));
            assert!(p.input.is_some());
            assert!(p.output.is_some());
        } else {
            panic!("Expected Procedure variant");
        }
    }

    #[test]
    fn deserialize_object_variant() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "object",
            "description": "A user profile",
            "required": ["displayName"],
            "nullable": ["avatar"],
            "properties": {
                "displayName": { "type": "string" },
                "avatar": { "type": "blob" }
            }
        }))
        .unwrap();
        if let LexUserType::Object(o) = &val {
            assert_eq!(o.required, vec!["displayName"]);
            assert_eq!(o.nullable, vec!["avatar"]);
            assert_eq!(o.properties.len(), 2);
        } else {
            panic!("Expected Object variant");
        }
    }

    #[test]
    fn deserialize_string_variant() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "string",
            "format": "at-uri",
            "minLength": 1,
            "maxLength": 100,
            "minGraphemes": 1,
            "maxGraphemes": 50
        }))
        .unwrap();
        if let LexUserType::String(s) = &val {
            assert_eq!(s.format.as_deref(), Some("at-uri"));
            assert_eq!(s.min_length, Some(1));
            assert_eq!(s.max_length, Some(100));
            assert_eq!(s.min_graphemes, Some(1));
            assert_eq!(s.max_graphemes, Some(50));
        } else {
            panic!("Expected String variant");
        }
    }

    #[test]
    fn deserialize_integer_variant() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "integer",
            "minimum": 0,
            "maximum": 100
        }))
        .unwrap();
        if let LexUserType::Integer(i) = &val {
            assert_eq!(i.minimum, Some(0));
            assert_eq!(i.maximum, Some(100));
        } else {
            panic!("Expected Integer variant");
        }
    }

    #[test]
    fn deserialize_array_variant() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "array",
            "items": { "type": "string" },
            "minLength": 0,
            "maxLength": 50
        }))
        .unwrap();
        if let LexUserType::Array(a) = &val {
            assert_eq!(a.items.type_name(), "string");
            assert_eq!(a.min_length, Some(0));
            assert_eq!(a.max_length, Some(50));
        } else {
            panic!("Expected Array variant");
        }
    }

    #[test]
    fn deserialize_ref_variant() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "ref",
            "ref": "com.example.defs#thing"
        }))
        .unwrap();
        if let LexUserType::Ref(r) = &val {
            assert_eq!(r.ref_target, "com.example.defs#thing");
        } else {
            panic!("Expected Ref variant");
        }
    }

    #[test]
    fn deserialize_union_variant() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "union",
            "refs": ["com.example.a", "com.example.b"],
            "closed": true
        }))
        .unwrap();
        if let LexUserType::Union(u) = &val {
            assert_eq!(u.refs, vec!["com.example.a", "com.example.b"]);
            assert_eq!(u.closed, Some(true));
        } else {
            panic!("Expected Union variant");
        }
    }

    // --- LexXrpcParameters deserialization ---

    #[test]
    fn deserialize_xrpc_parameters_with_required_and_properties() {
        let val: LexXrpcParameters = serde_json::from_value(json!({
            "required": ["limit", "cursor"],
            "properties": {
                "limit": { "type": "integer", "minimum": 1, "maximum": 100 },
                "cursor": { "type": "string" }
            }
        }))
        .unwrap();
        assert_eq!(val.required, vec!["limit", "cursor"]);
        assert_eq!(val.properties.len(), 2);
        assert_eq!(val.properties["limit"].type_name(), "integer");
        assert_eq!(val.properties["cursor"].type_name(), "string");
    }

    #[test]
    fn deserialize_xrpc_parameters_empty() {
        let val: LexXrpcParameters = serde_json::from_value(json!({})).unwrap();
        assert!(val.required.is_empty());
        assert!(val.properties.is_empty());
        assert!(val.description.is_none());
    }

    // --- LexString with enum_values, const_value, known_values ---

    #[test]
    fn lex_string_with_enum_values() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "string",
            "enum": ["trending", "hot", "latest"]
        }))
        .unwrap();
        if let LexUserType::String(s) = &val {
            assert_eq!(
                s.enum_values.as_deref(),
                Some(
                    vec![
                        "trending".to_string(),
                        "hot".to_string(),
                        "latest".to_string()
                    ]
                    .as_slice()
                )
            );
        } else {
            panic!("Expected String variant");
        }
    }

    #[test]
    fn lex_string_with_const_value() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "string",
            "const": "app.bsky.feed.post"
        }))
        .unwrap();
        if let LexUserType::String(s) = &val {
            assert_eq!(s.const_value.as_deref(), Some("app.bsky.feed.post"));
        } else {
            panic!("Expected String variant");
        }
    }

    #[test]
    fn lex_string_with_known_values() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "string",
            "knownValues": ["like", "repost", "follow"]
        }))
        .unwrap();
        if let LexUserType::String(s) = &val {
            let kv = s.known_values.as_ref().unwrap();
            assert_eq!(kv, &vec!["like", "repost", "follow"]);
        } else {
            panic!("Expected String variant");
        }
    }

    // --- LexInteger with minimum/maximum/enum_values ---

    #[test]
    fn lex_integer_with_enum_values() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "integer",
            "enum": [1, 2, 3]
        }))
        .unwrap();
        if let LexUserType::Integer(i) = &val {
            assert_eq!(i.enum_values.as_deref(), Some(&[1i64, 2, 3][..]));
        } else {
            panic!("Expected Integer variant");
        }
    }

    #[test]
    fn lex_integer_with_min_max_and_default() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "integer",
            "minimum": -100,
            "maximum": 999,
            "default": 50
        }))
        .unwrap();
        if let LexUserType::Integer(i) = &val {
            assert_eq!(i.minimum, Some(-100));
            assert_eq!(i.maximum, Some(999));
            assert_eq!(i.default, Some(50));
        } else {
            panic!("Expected Integer variant");
        }
    }

    // --- LexBlob with accept and max_size ---

    #[test]
    fn lex_blob_with_accept_and_max_size() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "blob",
            "accept": ["image/png", "image/jpeg"],
            "maxSize": 1000000
        }))
        .unwrap();
        if let LexUserType::Blob(b) = &val {
            assert_eq!(
                b.accept.as_ref().unwrap(),
                &vec!["image/png".to_string(), "image/jpeg".to_string()]
            );
            assert_eq!(b.max_size, Some(1000000));
        } else {
            panic!("Expected Blob variant");
        }
    }

    #[test]
    fn lex_blob_empty() {
        let val: LexUserType = serde_json::from_value(json!({"type": "blob"})).unwrap();
        if let LexUserType::Blob(b) = &val {
            assert!(b.accept.is_none());
            assert!(b.max_size.is_none());
        } else {
            panic!("Expected Blob variant");
        }
    }

    // --- LexRefUnion with refs and closed ---

    #[test]
    fn lex_ref_union_with_refs_and_closed() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "union",
            "refs": ["com.example.a#main", "com.example.b#main"],
            "closed": true
        }))
        .unwrap();
        if let LexUserType::Union(u) = &val {
            assert_eq!(u.refs.len(), 2);
            assert_eq!(u.closed, Some(true));
        } else {
            panic!("Expected Union variant");
        }
    }

    #[test]
    fn lex_ref_union_open_by_default() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "union",
            "refs": ["com.example.a"]
        }))
        .unwrap();
        if let LexUserType::Union(u) = &val {
            assert_eq!(u.refs, vec!["com.example.a"]);
            assert!(u.closed.is_none());
        } else {
            panic!("Expected Union variant");
        }
    }

    #[test]
    fn lex_ref_union_explicitly_open() {
        let val: LexUserType = serde_json::from_value(json!({
            "type": "union",
            "refs": ["com.example.a"],
            "closed": false
        }))
        .unwrap();
        if let LexUserType::Union(u) = &val {
            assert_eq!(u.closed, Some(false));
        } else {
            panic!("Expected Union variant");
        }
    }

    // --- Edge cases ---

    #[test]
    fn unknown_type_field_fails_deserialization() {
        let result = serde_json::from_value::<LexUserType>(json!({"type": "nonexistent"}));
        assert!(result.is_err());
    }

    #[test]
    fn missing_type_field_fails_deserialization() {
        let result = serde_json::from_value::<LexUserType>(json!({"description": "no type"}));
        assert!(result.is_err());
    }

    #[test]
    fn lexicon_doc_missing_defs_fails() {
        let result = serde_json::from_value::<LexiconDoc>(json!({
            "lexicon": 1,
            "id": "com.example.test"
        }));
        assert!(result.is_err());
    }
}
