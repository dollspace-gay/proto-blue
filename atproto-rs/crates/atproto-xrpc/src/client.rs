//! XRPC HTTP client implementation.

use std::collections::HashMap;

use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use url::Url;

use crate::error::{Error, ResponseType, XrpcError};
use crate::types::{CallOptions, HeadersMap, QueryParams, QueryValue, XrpcBody, XrpcResponse};

/// XRPC HTTP client for making AT Protocol API calls.
///
/// Handles query (GET) and procedure (POST) XRPC methods,
/// with URL construction, parameter encoding, and response parsing.
pub struct XrpcClient {
    /// The base service URL (e.g. `https://bsky.social`).
    service: Url,
    /// HTTP client.
    client: reqwest::Client,
    /// Default headers sent with every request.
    headers: HashMap<String, String>,
}

impl XrpcClient {
    /// Create a new XRPC client for the given service URL.
    pub fn new(service: impl AsRef<str>) -> Result<Self, Error> {
        let mut service_url = Url::parse(service.as_ref())?;
        // Ensure trailing slash for proper URL joining
        if !service_url.path().ends_with('/') {
            service_url.set_path(&format!("{}/", service_url.path()));
        }
        Ok(XrpcClient {
            service: service_url,
            client: reqwest::Client::new(),
            headers: HashMap::new(),
        })
    }

    /// Create a new XRPC client with a custom reqwest::Client.
    pub fn with_client(service: impl AsRef<str>, client: reqwest::Client) -> Result<Self, Error> {
        let mut service_url = Url::parse(service.as_ref())?;
        if !service_url.path().ends_with('/') {
            service_url.set_path(&format!("{}/", service_url.path()));
        }
        Ok(XrpcClient {
            service: service_url,
            client,
            headers: HashMap::new(),
        })
    }

    /// Get the service URL.
    pub fn service_url(&self) -> &Url {
        &self.service
    }

    /// Set the service URL.
    pub fn set_service(&mut self, service: impl AsRef<str>) -> Result<(), Error> {
        let mut service_url = Url::parse(service.as_ref())?;
        if !service_url.path().ends_with('/') {
            service_url.set_path(&format!("{}/", service_url.path()));
        }
        self.service = service_url;
        Ok(())
    }

    /// Set a default header that will be sent with every request.
    pub fn set_header(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.headers.insert(key.into().to_lowercase(), value.into());
    }

    /// Remove a default header.
    pub fn unset_header(&mut self, key: &str) {
        self.headers.remove(&key.to_lowercase());
    }

    /// Clear all default headers.
    pub fn clear_headers(&mut self) {
        self.headers.clear();
    }

    /// Make an XRPC query (GET) call.
    pub async fn query(
        &self,
        nsid: &str,
        params: Option<&QueryParams>,
        opts: Option<&CallOptions>,
    ) -> Result<XrpcResponse, Error> {
        let url = self.build_url(nsid, params)?;
        let mut req = self.client.get(url);
        req = self.apply_headers(req, opts);

        let response = req.send().await?;
        self.handle_response(response).await
    }

    /// Make an XRPC procedure (POST) call.
    pub async fn procedure(
        &self,
        nsid: &str,
        params: Option<&QueryParams>,
        body: Option<XrpcBody>,
        opts: Option<&CallOptions>,
    ) -> Result<XrpcResponse, Error> {
        let url = self.build_url(nsid, params)?;
        let mut req = self.client.post(url);
        req = self.apply_headers(req, opts);

        // Set body
        match body {
            Some(XrpcBody::Json(value)) => {
                req = req.header(CONTENT_TYPE, "application/json").json(&value);
            }
            Some(XrpcBody::Bytes(data)) => {
                let encoding = opts
                    .and_then(|o| o.encoding.as_deref())
                    .unwrap_or("application/octet-stream");
                req = req.header(CONTENT_TYPE, encoding).body(data);
            }
            None => {}
        }

        let response = req.send().await?;
        self.handle_response(response).await
    }

    /// Generic call method — determines GET/POST based on the `method` parameter.
    pub async fn call(
        &self,
        method: HttpMethod,
        nsid: &str,
        params: Option<&QueryParams>,
        body: Option<XrpcBody>,
        opts: Option<&CallOptions>,
    ) -> Result<XrpcResponse, Error> {
        match method {
            HttpMethod::Get => self.query(nsid, params, opts).await,
            HttpMethod::Post => self.procedure(nsid, params, body, opts).await,
        }
    }

    /// Build the full URL for an XRPC call.
    fn build_url(&self, nsid: &str, params: Option<&QueryParams>) -> Result<Url, Error> {
        let path = format!("xrpc/{}", nsid);
        let mut url = self.service.join(&path)?;

        if let Some(params) = params {
            let mut query_pairs = url.query_pairs_mut();
            for (key, value) in params {
                match value {
                    QueryValue::Array(values) => {
                        for v in values {
                            query_pairs.append_pair(key, &v.encode());
                        }
                    }
                    _ => {
                        query_pairs.append_pair(key, &value.encode());
                    }
                }
            }
        }

        Ok(url)
    }

    /// Apply default headers and call-specific headers to a request.
    fn apply_headers(
        &self,
        mut req: reqwest::RequestBuilder,
        opts: Option<&CallOptions>,
    ) -> reqwest::RequestBuilder {
        // Apply default headers
        let mut header_map = HeaderMap::new();
        for (key, value) in &self.headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                header_map.insert(name, val);
            }
        }

        // Apply call-specific headers (override defaults)
        if let Some(opts) = opts {
            if let Some(call_headers) = &opts.headers {
                for (key, value) in call_headers {
                    if let (Ok(name), Ok(val)) = (
                        HeaderName::from_bytes(key.to_lowercase().as_bytes()),
                        HeaderValue::from_str(value),
                    ) {
                        header_map.insert(name, val);
                    }
                }
            }
        }

        if !header_map.is_empty() {
            req = req.headers(header_map);
        }
        req
    }

    /// Process an HTTP response into an XrpcResponse or XrpcError.
    async fn handle_response(&self, response: reqwest::Response) -> Result<XrpcResponse, Error> {
        let status = response.status().as_u16();
        let response_type = ResponseType::from_http_status(status);

        // Collect response headers
        let headers: HeadersMap = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let body_bytes = response.bytes().await?;

        if response_type != ResponseType::Success {
            // Try to parse error response body
            let (error, message) = if let Some(ref ct) = content_type {
                if ct.contains("application/json") {
                    parse_error_body(&body_bytes)
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            return Err(Error::Xrpc(XrpcError {
                status: response_type,
                error,
                message,
                headers: Some(headers),
            }));
        }

        // Parse response body based on content type
        let data = parse_response_body(content_type.as_deref(), &body_bytes);

        Ok(XrpcResponse { data, headers })
    }
}

/// HTTP method for XRPC calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// Parse an error response body to extract error/message fields.
fn parse_error_body(bytes: &[u8]) -> (Option<String>, Option<String>) {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
        let error = value
            .get("error")
            .and_then(|v| v.as_str())
            .map(String::from);
        let message = value
            .get("message")
            .and_then(|v| v.as_str())
            .map(String::from);
        (error, message)
    } else {
        (None, None)
    }
}

/// Parse a response body based on content type.
fn parse_response_body(content_type: Option<&str>, bytes: &[u8]) -> serde_json::Value {
    if let Some(ct) = content_type {
        if ct.contains("application/json") {
            if let Ok(value) = serde_json::from_slice(bytes) {
                return value;
            }
        }
        if ct.starts_with("text/") {
            if let Ok(text) = std::str::from_utf8(bytes) {
                return serde_json::Value::String(text.to_string());
            }
        }
    }

    // Return raw bytes as null if empty, or as a JSON value if possible
    if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        // For binary data, we can't represent it as JSON directly.
        // Return as a JSON string of the base64-encoded data.
        use serde_json::json;
        json!({ "$bytes": base64_encode(bytes) })
    }
}

fn base64_encode(data: &[u8]) -> String {
    // Simple base64 encoding using a lookup table
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[(n >> 18 & 63) as usize] as char);
        result.push(CHARS[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[(n >> 6 & 63) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_url_no_params() {
        let client = XrpcClient::new("https://bsky.social").unwrap();
        let url = client
            .build_url("com.atproto.server.describeServer", None)
            .unwrap();
        assert_eq!(
            url.as_str(),
            "https://bsky.social/xrpc/com.atproto.server.describeServer"
        );
    }

    #[test]
    fn build_url_with_params() {
        let client = XrpcClient::new("https://bsky.social").unwrap();
        let mut params = QueryParams::new();
        params.insert(
            "actor".to_string(),
            QueryValue::String("did:plc:test".to_string()),
        );
        let url = client
            .build_url("app.bsky.actor.getProfile", Some(&params))
            .unwrap();
        assert!(url.as_str().contains("/xrpc/app.bsky.actor.getProfile"));
        assert!(url.as_str().contains("actor=did%3Aplc%3Atest"));
    }

    #[test]
    fn build_url_with_array_params() {
        let client = XrpcClient::new("https://bsky.social").unwrap();
        let mut params = QueryParams::new();
        params.insert(
            "uris".to_string(),
            QueryValue::Array(vec![
                QueryValue::String("at://a".to_string()),
                QueryValue::String("at://b".to_string()),
            ]),
        );
        let url = client
            .build_url("app.bsky.feed.getPosts", Some(&params))
            .unwrap();
        let url_str = url.as_str();
        assert!(url_str.contains("uris=at%3A%2F%2Fa"));
        assert!(url_str.contains("uris=at%3A%2F%2Fb"));
    }

    #[test]
    fn build_url_with_boolean_param() {
        let client = XrpcClient::new("https://bsky.social").unwrap();
        let mut params = QueryParams::new();
        params.insert("includeTakedowns".to_string(), QueryValue::Boolean(true));
        let url = client
            .build_url("com.atproto.admin.getRecord", Some(&params))
            .unwrap();
        assert!(url.as_str().contains("includeTakedowns=true"));
    }

    #[test]
    fn build_url_with_integer_param() {
        let client = XrpcClient::new("https://bsky.social").unwrap();
        let mut params = QueryParams::new();
        params.insert("limit".to_string(), QueryValue::Integer(50));
        let url = client
            .build_url("app.bsky.feed.getTimeline", Some(&params))
            .unwrap();
        assert!(url.as_str().contains("limit=50"));
    }

    #[test]
    fn client_new_with_trailing_slash() {
        let client = XrpcClient::new("https://bsky.social/").unwrap();
        assert_eq!(client.service_url().as_str(), "https://bsky.social/");
    }

    #[test]
    fn client_new_without_trailing_slash() {
        let client = XrpcClient::new("https://bsky.social").unwrap();
        assert_eq!(client.service_url().as_str(), "https://bsky.social/");
    }

    #[test]
    fn response_type_from_http_status() {
        assert_eq!(ResponseType::from_http_status(200), ResponseType::Success);
        assert_eq!(
            ResponseType::from_http_status(401),
            ResponseType::AuthenticationRequired
        );
        assert_eq!(
            ResponseType::from_http_status(429),
            ResponseType::RateLimitExceeded
        );
        assert_eq!(
            ResponseType::from_http_status(500),
            ResponseType::InternalServerError
        );
        // Unmapped codes fall to range defaults
        assert_eq!(
            ResponseType::from_http_status(418),
            ResponseType::InvalidRequest
        );
        assert_eq!(ResponseType::from_http_status(201), ResponseType::Success);
        assert_eq!(
            ResponseType::from_http_status(503),
            ResponseType::NotEnoughResources
        );
    }

    #[test]
    fn response_type_display() {
        assert_eq!(ResponseType::Success.to_string(), "Success");
        assert_eq!(
            ResponseType::AuthenticationRequired.to_string(),
            "Authentication Required"
        );
        assert_eq!(
            ResponseType::RateLimitExceeded.to_string(),
            "Rate Limit Exceeded"
        );
    }

    #[test]
    fn xrpc_error_display() {
        let err = XrpcError {
            status: ResponseType::AuthenticationRequired,
            error: Some("AuthenticationRequired".into()),
            message: Some("Invalid token".into()),
            headers: None,
        };
        assert_eq!(err.to_string(), "Invalid token");

        let err2 = XrpcError {
            status: ResponseType::Forbidden,
            error: Some("Forbidden".into()),
            message: None,
            headers: None,
        };
        assert_eq!(err2.to_string(), "Forbidden");
    }

    #[test]
    fn xrpc_error_is_error() {
        let err = XrpcError {
            status: ResponseType::InvalidRequest,
            error: Some("InvalidToken".into()),
            message: None,
            headers: None,
        };
        assert!(err.is_error("InvalidToken"));
        assert!(!err.is_error("ExpiredToken"));
    }

    #[test]
    fn parse_error_body_json() {
        let body = br#"{"error":"InvalidToken","message":"Token expired"}"#;
        let (error, message) = parse_error_body(body);
        assert_eq!(error.as_deref(), Some("InvalidToken"));
        assert_eq!(message.as_deref(), Some("Token expired"));
    }

    #[test]
    fn parse_error_body_invalid() {
        let (error, message) = parse_error_body(b"not json");
        assert!(error.is_none());
        assert!(message.is_none());
    }

    #[test]
    fn parse_response_body_json() {
        let body = br#"{"did":"did:plc:test","handle":"test.bsky.social"}"#;
        let value = parse_response_body(Some("application/json"), body);
        assert_eq!(value["did"], "did:plc:test");
        assert_eq!(value["handle"], "test.bsky.social");
    }

    #[test]
    fn parse_response_body_text() {
        let body = b"Hello, world!";
        let value = parse_response_body(Some("text/plain"), body);
        assert_eq!(value, serde_json::Value::String("Hello, world!".into()));
    }

    #[test]
    fn parse_response_body_empty() {
        let value = parse_response_body(None, b"");
        assert_eq!(value, serde_json::Value::Null);
    }

    #[test]
    fn query_value_encode() {
        assert_eq!(QueryValue::String("hello".into()).encode(), "hello");
        assert_eq!(QueryValue::Integer(42).encode(), "42");
        assert_eq!(QueryValue::Float(3.14).encode(), "3.14");
        assert_eq!(QueryValue::Boolean(true).encode(), "true");
        assert_eq!(QueryValue::Boolean(false).encode(), "false");
    }

    #[test]
    fn query_value_from_conversions() {
        let _: QueryValue = "hello".into();
        let _: QueryValue = String::from("hello").into();
        let _: QueryValue = 42i64.into();
        let _: QueryValue = 3.14f64.into();
        let _: QueryValue = true.into();
        let _: QueryValue = vec!["a", "b"].into();
    }

    #[test]
    fn set_and_unset_headers() {
        let mut client = XrpcClient::new("https://bsky.social").unwrap();
        client.set_header("Authorization", "Bearer token123");
        assert_eq!(
            client.headers.get("authorization"),
            Some(&"Bearer token123".to_string())
        );
        client.unset_header("Authorization");
        assert!(client.headers.get("authorization").is_none());
    }

    #[test]
    fn clear_headers() {
        let mut client = XrpcClient::new("https://bsky.social").unwrap();
        client.set_header("Authorization", "Bearer token123");
        client.set_header("X-Custom", "value");
        assert_eq!(client.headers.len(), 2);
        client.clear_headers();
        assert!(client.headers.is_empty());
    }

    #[test]
    fn set_service() {
        let mut client = XrpcClient::new("https://bsky.social").unwrap();
        client.set_service("https://other.example.com").unwrap();
        assert_eq!(client.service_url().as_str(), "https://other.example.com/");
    }

    #[test]
    fn base64_encode_basic() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn http_method_debug() {
        assert_eq!(format!("{:?}", HttpMethod::Get), "Get");
        assert_eq!(format!("{:?}", HttpMethod::Post), "Post");
    }
}
