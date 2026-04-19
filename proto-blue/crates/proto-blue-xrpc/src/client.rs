//! XRPC HTTP client implementation.
//!
//! The client is transport-agnostic: it constructs a
//! [`proto_blue_common::fetch::HttpRequest`] and hands it off to a
//! [`FetchHandler`]. Two implementations ship in `proto-blue-common`:
//!
//! - [`proto_blue_common::fetch::ReqwestFetcher`] (feature
//!   `fetch-reqwest`, default) — native HTTP via `reqwest`.
//! - [`proto_blue_common::fetch::WebFetcher`] (feature `fetch-web`) —
//!   browser `fetch()` via `gloo-net`, for `wasm32-unknown-unknown`.
//!
//! Callers can also supply their own implementation, which is the primary
//! seam for unit-testable mocks.

use std::collections::HashMap;
use std::sync::Arc;

use proto_blue_common::fetch::{FetchHandler, HttpMethod as CommonMethod, HttpRequest};
use url::Url;

use crate::error::{Error, ResponseType, XrpcError};
use crate::types::{CallOptions, HeadersMap, QueryParams, QueryValue, XrpcBody, XrpcResponse};

/// XRPC HTTP client for making AT Protocol API calls.
///
/// Handles query (GET) and procedure (POST) XRPC methods, URL
/// construction, parameter encoding, and response parsing. The actual HTTP
/// transport is abstracted behind [`FetchHandler`].
pub struct XrpcClient {
    /// The base service URL (e.g. `https://bsky.social`).
    service: Url,
    /// HTTP transport.
    fetcher: Arc<dyn FetchHandler>,
    /// Default headers sent with every request (lowercase keys).
    headers: HashMap<String, String>,
}

impl XrpcClient {
    /// Create a new XRPC client using the crate's default [`FetchHandler`].
    ///
    /// With the `fetch-reqwest` feature (default on native), this uses a
    /// fresh `reqwest::Client`. With only `fetch-web`, it uses
    /// [`web_fetch::WebFetcher`]. If neither feature is enabled, callers
    /// must construct the client via [`Self::with_fetch_handler`].
    #[cfg(any(feature = "fetch-reqwest", feature = "fetch-web"))]
    pub fn new(service: impl AsRef<str>) -> Result<Self, Error> {
        Self::with_fetch_handler(service, Arc::new(default_fetcher()))
    }

    /// Create a new XRPC client backed by a custom [`FetchHandler`].
    ///
    /// Primary extension point for callers who want to inject a mock, a
    /// proxying transport, a custom TLS configuration, or — on
    /// wasm32-unknown-unknown — a browser-native fetch implementation.
    pub fn with_fetch_handler(
        service: impl AsRef<str>,
        fetcher: Arc<dyn FetchHandler>,
    ) -> Result<Self, Error> {
        let mut service_url = Url::parse(service.as_ref())?;
        if !service_url.path().ends_with('/') {
            service_url.set_path(&format!("{}/", service_url.path()));
        }
        Ok(XrpcClient {
            service: service_url,
            fetcher,
            headers: HashMap::new(),
        })
    }

    /// Create a new XRPC client that wraps a user-supplied `reqwest::Client`.
    ///
    /// Feature-gated behind `fetch-reqwest`.
    #[cfg(feature = "fetch-reqwest")]
    pub fn with_client(
        service: impl AsRef<str>,
        client: reqwest::Client,
    ) -> Result<Self, Error> {
        Self::with_fetch_handler(
            service,
            Arc::new(proto_blue_common::fetch::ReqwestFetcher::from_client(client)),
        )
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
        let req = self.build_request(CommonMethod::Get, url, opts, None);
        self.send(req).await
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
        let req = self.build_request(CommonMethod::Post, url, opts, body);
        self.send(req).await
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

    /// Construct a transport-independent [`HttpRequest`], applying default
    /// headers, per-call header overrides, and any body.
    fn build_request(
        &self,
        method: CommonMethod,
        url: Url,
        opts: Option<&CallOptions>,
        body: Option<XrpcBody>,
    ) -> HttpRequest {
        let mut req = HttpRequest {
            method,
            url: url.into(),
            headers: Default::default(),
            body: None,
        };

        // Apply default headers.
        for (key, value) in &self.headers {
            req.headers.insert(key.clone(), value.clone());
        }

        // Apply call-specific headers (override defaults).
        if let Some(opts) = opts
            && let Some(call_headers) = &opts.headers
        {
            for (key, value) in call_headers {
                req.headers.insert(key.to_lowercase(), value.clone());
            }
        }

        // Body + Content-Type.
        if let Some(body) = body {
            match body {
                XrpcBody::Json(value) => {
                    req.headers
                        .entry("content-type".to_string())
                        .or_insert_with(|| "application/json".to_string());
                    req.body = Some(
                        serde_json::to_vec(&value).expect("JSON serialization cannot fail"),
                    );
                }
                XrpcBody::Bytes(data) => {
                    let encoding = opts
                        .and_then(|o| o.encoding.as_deref())
                        .unwrap_or("application/octet-stream")
                        .to_string();
                    req.headers.insert("content-type".to_string(), encoding);
                    req.body = Some(data);
                }
            }
        }

        req
    }

    /// Dispatch a pre-built request through the [`FetchHandler`] and
    /// interpret the response.
    async fn send(&self, req: HttpRequest) -> Result<XrpcResponse, Error> {
        let response = self.fetcher.fetch(req).await.map_err(Error::Fetch)?;

        let status = response.status;
        let response_type = ResponseType::from_http_status(status);

        let headers: HeadersMap = response.headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let content_type = response
            .header("content-type")
            .map(|s| s.to_string());

        let body_bytes = response.body;

        if response_type != ResponseType::Success {
            let (error, message) = if let Some(ref ct) = content_type
                && ct.contains("application/json")
            {
                parse_error_body(&body_bytes)
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

        let data = parse_response_body(content_type.as_deref(), &body_bytes);

        Ok(XrpcResponse { data, headers })
    }
}

/// Construct the default [`FetchHandler`] for this crate's feature set.
///
/// Prefers `fetch-reqwest` when available. On wasm-only builds, falls back
/// to `fetch-web`.
#[cfg(feature = "fetch-reqwest")]
fn default_fetcher() -> proto_blue_common::fetch::ReqwestFetcher {
    proto_blue_common::fetch::ReqwestFetcher::new()
}

#[cfg(all(feature = "fetch-web", not(feature = "fetch-reqwest"), target_arch = "wasm32"))]
fn default_fetcher() -> proto_blue_common::fetch::WebFetcher {
    proto_blue_common::fetch::WebFetcher::new()
}

/// HTTP method for XRPC calls.
///
/// XRPC only defines GET (query) and POST (procedure); the broader set of
/// HTTP methods lives in [`proto_blue_common::fetch::HttpMethod`].
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

    if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        use serde_json::json;
        json!({ "$bytes": base64_encode(bytes) })
    }
}

fn base64_encode(data: &[u8]) -> String {
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

#[cfg(all(test, feature = "fetch-reqwest"))]
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
        assert_eq!(QueryValue::Float(2.5).encode(), "2.5");
        assert_eq!(QueryValue::Boolean(true).encode(), "true");
        assert_eq!(QueryValue::Boolean(false).encode(), "false");
    }

    #[test]
    fn query_value_from_conversions() {
        let _: QueryValue = "hello".into();
        let _: QueryValue = String::from("hello").into();
        let _: QueryValue = 42i64.into();
        let _: QueryValue = 2.5f64.into();
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
        assert!(!client.headers.contains_key("authorization"));
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
