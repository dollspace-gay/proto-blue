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

#[cfg(test)]
mod tests {
    use super::*;

    // ── QueryValue::encode() ─────────────────────────────────────────

    #[test]
    fn encode_string() {
        let v = QueryValue::String("hello".into());
        assert_eq!(v.encode(), "hello");
    }

    #[test]
    fn encode_integer() {
        let v = QueryValue::Integer(42);
        assert_eq!(v.encode(), "42");
    }

    #[test]
    fn encode_negative_integer() {
        let v = QueryValue::Integer(-7);
        assert_eq!(v.encode(), "-7");
    }

    #[test]
    fn encode_float() {
        // Avoid values that trigger `clippy::approx_constant` (π, e, etc.)
        // — this test only cares that a float round-trips its Display form.
        let v = QueryValue::Float(2.5);
        assert_eq!(v.encode(), "2.5");
    }

    #[test]
    fn encode_boolean_true() {
        let v = QueryValue::Boolean(true);
        assert_eq!(v.encode(), "true");
    }

    #[test]
    fn encode_boolean_false() {
        let v = QueryValue::Boolean(false);
        assert_eq!(v.encode(), "false");
    }

    #[test]
    fn encode_array_returns_empty_string() {
        let v = QueryValue::Array(vec![QueryValue::String("a".into())]);
        assert_eq!(v.encode(), "");
    }

    // ── From conversions ─────────────────────────────────────────────

    #[test]
    fn from_str_ref() {
        let v: QueryValue = "hello".into();
        assert_eq!(v.encode(), "hello");
    }

    #[test]
    fn from_string() {
        let v: QueryValue = String::from("world").into();
        assert_eq!(v.encode(), "world");
    }

    #[test]
    fn from_i64() {
        let v: QueryValue = 99i64.into();
        assert_eq!(v.encode(), "99");
    }

    #[test]
    fn from_f64() {
        let v: QueryValue = 2.5f64.into();
        assert_eq!(v.encode(), "2.5");
    }

    #[test]
    fn from_bool() {
        let v: QueryValue = true.into();
        assert_eq!(v.encode(), "true");
    }

    #[test]
    fn from_vec_string() {
        let v: QueryValue = vec!["a".to_string(), "b".to_string()].into();
        match v {
            QueryValue::Array(items) => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0].encode(), "a");
                assert_eq!(items[1].encode(), "b");
            }
            _ => panic!("expected Array variant"),
        }
    }

    // ── CallOptions ──────────────────────────────────────────────────

    #[test]
    fn call_options_default_has_none_fields() {
        let opts = CallOptions::default();
        assert!(opts.encoding.is_none());
        assert!(opts.headers.is_none());
    }

    // ── XrpcBody ─────────────────────────────────────────────────────

    #[test]
    fn xrpc_body_json_construction() {
        let body = XrpcBody::Json(serde_json::json!({"key": "value"}));
        match body {
            XrpcBody::Json(v) => assert_eq!(v["key"], "value"),
            _ => panic!("expected Json variant"),
        }
    }

    #[test]
    fn xrpc_body_bytes_construction() {
        let data = vec![0u8, 1, 2, 3];
        let body = XrpcBody::Bytes(data.clone());
        match body {
            XrpcBody::Bytes(b) => assert_eq!(b, data),
            _ => panic!("expected Bytes variant"),
        }
    }

    // ── XrpcResponse ─────────────────────────────────────────────────

    #[test]
    fn xrpc_response_construction_and_field_access() {
        let mut headers = HeadersMap::new();
        headers.insert("content-type".into(), "application/json".into());

        let resp = XrpcResponse {
            data: serde_json::json!({"ok": true}),
            headers,
        };

        assert_eq!(resp.data["ok"], true);
        assert_eq!(resp.headers["content-type"], "application/json");
    }

    #[test]
    fn xrpc_response_empty_headers() {
        let resp = XrpcResponse {
            data: serde_json::json!(null),
            headers: HeadersMap::new(),
        };

        assert!(resp.data.is_null());
        assert!(resp.headers.is_empty());
    }
}
