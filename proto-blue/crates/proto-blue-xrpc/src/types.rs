//! XRPC request/response types.

use std::collections::HashMap;

/// Query parameters for XRPC calls.
pub type QueryParams = HashMap<String, QueryValue>;

/// A single query parameter value.
#[derive(Debug, Clone)]
pub enum QueryValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    /// Array of values (for repeated parameters like `?tag=a&tag=b`).
    Array(Vec<QueryValue>),
}

impl QueryValue {
    /// Encode this value as a query string value.
    pub fn encode(&self) -> String {
        match self {
            QueryValue::String(s) => s.clone(),
            QueryValue::Integer(i) => i.to_string(),
            QueryValue::Float(f) => f.to_string(),
            QueryValue::Boolean(b) => if *b { "true" } else { "false" }.to_string(),
            QueryValue::Array(_) => String::new(), // handled separately
        }
    }
}

impl From<&str> for QueryValue {
    fn from(s: &str) -> Self {
        QueryValue::String(s.to_string())
    }
}

impl From<String> for QueryValue {
    fn from(s: String) -> Self {
        QueryValue::String(s)
    }
}

impl From<i64> for QueryValue {
    fn from(i: i64) -> Self {
        QueryValue::Integer(i)
    }
}

impl From<f64> for QueryValue {
    fn from(f: f64) -> Self {
        QueryValue::Float(f)
    }
}

impl From<bool> for QueryValue {
    fn from(b: bool) -> Self {
        QueryValue::Boolean(b)
    }
}

impl<T: Into<QueryValue>> From<Vec<T>> for QueryValue {
    fn from(v: Vec<T>) -> Self {
        QueryValue::Array(v.into_iter().map(Into::into).collect())
    }
}

/// Headers map for XRPC requests/responses.
pub type HeadersMap = HashMap<String, String>;

/// Options for an XRPC call.
#[derive(Debug, Default, Clone)]
pub struct CallOptions {
    /// Content encoding for the request body.
    pub encoding: Option<String>,
    /// Additional headers to include.
    pub headers: Option<HeadersMap>,
}

/// Successful XRPC response.
#[derive(Debug)]
pub struct XrpcResponse {
    /// Parsed response body.
    pub data: serde_json::Value,
    /// Response headers.
    pub headers: HeadersMap,
}

/// Body data for XRPC procedure calls.
#[derive(Debug)]
pub enum XrpcBody {
    /// JSON data (will be serialized as application/json).
    Json(serde_json::Value),
    /// Raw bytes (application/octet-stream or custom encoding).
    Bytes(Vec<u8>),
}
