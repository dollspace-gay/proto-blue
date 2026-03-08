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
