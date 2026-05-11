//! Transport-agnostic HTTP fetch abstraction.
//!
//! Mirrors the TypeScript SDK's `@atproto/xrpc` `FetchHandler` pattern: a
//! small trait over a request/response pair that higher layers call instead
//! of reaching for `reqwest` (or any other HTTP client) directly.
//!
//! # Backends
//!
//! Two implementations ship with this crate:
//!
//! - `ReqwestFetcher` (feature `fetch-reqwest`, default on native) —
//!   backed by `reqwest`. Target-gated to `not(target_arch = "wasm32")`
//!   in `Cargo.toml` so enabling `fetch-reqwest` on wasm is a no-op.
//! - `WebFetcher` (always available on wasm32) — backed by `gloo-net`
//!   which drives the browser's native `fetch()`.
//!
//! Callers can also supply their own implementation, which is the primary
//! seam for unit-testable mocks.
//!
//! # Why a trait here, not in `proto-blue-xrpc`?
//!
//! Identity resolution (`proto-blue-identity`), OAuth metadata discovery
//! (`proto-blue-oauth`), and XRPC calls (`proto-blue-xrpc`) all need to
//! issue HTTP requests. Keeping the trait and the shared adapters in
//! `proto-blue-common` means a single reusable abstraction all three can
//! consume — and swap for a browser-native backend on wasm without each
//! crate inventing its own.
//!
//! # Send bounds
//!
//! On native targets, futures returned by the trait are `Send` so they can
//! be spawned onto a multi-threaded runtime. On `wasm32-unknown-unknown`
//! futures are not `Send` (JS promises aren't thread-safe) so the trait is
//! emitted with `?Send`. Both shapes have the same method signature — user
//! code doesn't need to branch on target.

use std::collections::BTreeMap;

use async_trait::async_trait;
use thiserror::Error;

// `reqwest_impl` is native-only — the `reqwest` dep is gated behind
// `cfg(not(target_arch = "wasm32"))` in Cargo.toml, so enabling
// `fetch-reqwest` on wasm must be a no-op rather than a compile error.
#[cfg(all(feature = "fetch-reqwest", not(target_arch = "wasm32")))]
pub mod reqwest_impl;

// `web_impl` is always compiled on wasm — its deps (gloo-net, js-sys)
// are target-conditional non-optional, so downstream callers don't
// have to enable `fetch-web` to get a default fetcher.
#[cfg(target_arch = "wasm32")]
pub mod web_impl;

#[cfg(all(feature = "fetch-reqwest", not(target_arch = "wasm32")))]
pub use reqwest_impl::ReqwestFetcher;

#[cfg(target_arch = "wasm32")]
pub use web_impl::WebFetcher;

/// Ordered map of lowercase header names to values.
///
/// Using `BTreeMap` (not `HashMap`) gives deterministic ordering — useful
/// for test vectors, `DPoP` canonicalisation, and request logging.
pub type HttpHeaders = BTreeMap<String, String>;

/// HTTP method for an outbound request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

impl HttpMethod {
    /// Canonical uppercase string (e.g. `"GET"`).
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }
}

/// A transport-independent HTTP request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    /// Absolute URL, including query string.
    pub url: String,
    /// Request headers. Keys should be lowercase.
    pub headers: HttpHeaders,
    /// Optional request body — `None` for GET/DELETE/HEAD.
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    /// Build a bodyless GET request.
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Get,
            url: url.into(),
            headers: HttpHeaders::new(),
            body: None,
        }
    }

    /// Build a POST request with no body.
    pub fn post(url: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Post,
            url: url.into(),
            headers: HttpHeaders::new(),
            body: None,
        }
    }

    /// Set a header (lowercasing the key to match `HttpHeaders` convention).
    #[must_use]
    pub fn with_header(mut self, key: impl AsRef<str>, value: impl Into<String>) -> Self {
        self.headers
            .insert(key.as_ref().to_lowercase(), value.into());
        self
    }

    /// Attach a request body.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }
}

/// A transport-independent HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HttpHeaders,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// `true` when `status` is in the 2xx range.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Return the HTTP status as an [`http::StatusCode`] — the same
    /// type reqwest returns from `reqwest::Response::status`, so
    /// callers coming from a `reqwest::Response` can use
    /// `resp.status().is_success()` / `resp.status() == StatusCode::UNAUTHORIZED`
    /// without change.
    ///
    /// Falls back to `INTERNAL_SERVER_ERROR` (500) if the raw status
    /// is outside the valid u16 range (1–999) — which shouldn't happen
    /// in practice but keeps this infallible.
    #[must_use]
    pub fn status(&self) -> http::StatusCode {
        http::StatusCode::from_u16(self.status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// Look up a header by case-insensitive name.
    #[must_use]
    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers
            .get(&key.to_lowercase())
            .map(std::string::String::as_str)
    }

    /// Consume the response and return the body as a UTF-8 string.
    /// Mirrors `reqwest::Response::text`. The `async` signature is kept
    /// for source-compatibility with reqwest callers even though no
    /// I/O is performed here — the body is already buffered.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::Body`] when the body is not valid UTF-8.
    // API signature stability: mirrors reqwest::Response::text which is async.
    #[allow(clippy::unused_async)]
    pub async fn text(self) -> Result<String, FetchError> {
        String::from_utf8(self.body)
            .map_err(|e| FetchError::Body(format!("response body is not utf-8: {e}")))
    }

    /// Consume the response and deserialize the body from JSON.
    /// Mirrors `reqwest::Response::json`. `async` for source-
    /// compatibility with reqwest callers.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::Body`] when the body isn't valid JSON
    /// for the requested type `T`.
    // API signature stability: mirrors reqwest::Response::json which is async.
    #[allow(clippy::unused_async)]
    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T, FetchError> {
        serde_json::from_slice(&self.body)
            .map_err(|e| FetchError::Body(format!("response body is not json: {e}")))
    }
}

/// Re-export of [`http::StatusCode`] so callers can refer to it
/// without adding `http` as an explicit dependency.
pub use http::StatusCode;

/// Errors surfaced by a [`FetchHandler`] implementation.
#[derive(Debug, Error)]
pub enum FetchError {
    /// Network-level problem (connection refused, DNS failure, TLS, etc.).
    #[error("network error: {0}")]
    Network(String),
    /// Request URL did not parse.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    /// Failed to read the response body.
    #[error("response body error: {0}")]
    Body(String),
    /// Timed out before the response arrived.
    #[error("request timed out")]
    Timeout,
    /// Catch-all for backend-specific errors.
    #[error("{0}")]
    Other(String),
}

/// A trait for issuing HTTP requests.
///
/// On native targets, futures are `Send` so the handler can drive a
/// multi-threaded runtime. On `wasm32-unknown-unknown` the futures are
/// `!Send`, matching the single-threaded JavaScript host.
///
/// # Example — calling into a handler
///
/// ```no_run
/// use std::sync::Arc;
/// use proto_blue_common::fetch::{FetchHandler, HttpRequest};
///
/// # async fn run(handler: Arc<dyn FetchHandler>) -> Result<(), Box<dyn std::error::Error>> {
/// let req = HttpRequest::get("https://example.com/health")
///     .with_header("accept", "application/json");
/// let res = handler.fetch(req).await?;
/// assert!(res.is_success());
/// # Ok(()) }
/// ```
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait FetchHandler: Send + Sync {
    /// Send `req` and return its response, or an error.
    async fn fetch(&self, req: HttpRequest) -> Result<HttpResponse, FetchError>;
}

/// A trait for issuing HTTP requests. Wasm variant: the returned
/// future is `?Send` (since `gloo-net` / browser `fetch` futures
/// aren't `Send`), but the handler itself is still `Send + Sync` so
/// it can live inside `Arc<dyn FetchHandler>` fields on types that
/// need thread-safety markers (notably Bevy `Resource`s). On
/// single-threaded wasm this is vacuously true.
#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait FetchHandler: Send + Sync {
    /// Send `req` and return its response, or an error.
    async fn fetch(&self, req: HttpRequest) -> Result<HttpResponse, FetchError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request_builders_set_method_and_url() {
        let r = HttpRequest::get("https://example.com/a");
        assert_eq!(r.method, HttpMethod::Get);
        assert_eq!(r.url, "https://example.com/a");
        assert!(r.body.is_none());

        let p = HttpRequest::post("https://example.com/b");
        assert_eq!(p.method, HttpMethod::Post);
    }

    #[test]
    fn with_header_lowercases_key() {
        let r = HttpRequest::get("https://example.com").with_header("Accept", "application/json");
        assert_eq!(
            r.headers.get("accept").map(String::as_str),
            Some("application/json")
        );
        assert!(!r.headers.contains_key("Accept"));
    }

    #[test]
    fn with_body_attaches_body() {
        let r = HttpRequest::post("https://example.com").with_body(vec![1, 2, 3]);
        assert_eq!(r.body.as_deref(), Some([1u8, 2, 3].as_ref()));
    }

    #[test]
    fn http_method_as_str_matches_canonical_uppercase() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Post.as_str(), "POST");
        assert_eq!(HttpMethod::Put.as_str(), "PUT");
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
        assert_eq!(HttpMethod::Patch.as_str(), "PATCH");
        assert_eq!(HttpMethod::Head.as_str(), "HEAD");
        assert_eq!(HttpMethod::Options.as_str(), "OPTIONS");
    }

    #[test]
    fn http_response_is_success_covers_2xx() {
        for s in 200u16..300 {
            let r = HttpResponse {
                status: s,
                headers: HttpHeaders::new(),
                body: vec![],
            };
            assert!(r.is_success(), "{s} should be success");
        }
        for s in [100u16, 199, 300, 400, 500, 599] {
            let r = HttpResponse {
                status: s,
                headers: HttpHeaders::new(),
                body: vec![],
            };
            assert!(!r.is_success(), "{s} should not be success");
        }
    }

    #[test]
    fn http_response_header_is_case_insensitive() {
        let mut headers = HttpHeaders::new();
        headers.insert("content-type".into(), "application/json".into());
        let r = HttpResponse {
            status: 200,
            headers,
            body: vec![],
        };
        assert_eq!(r.header("content-type"), Some("application/json"));
        assert_eq!(r.header("Content-Type"), Some("application/json"));
        assert_eq!(r.header("missing"), None);
    }

    #[test]
    fn fetch_error_display_includes_backend_message() {
        let e = FetchError::Network("EHOSTUNREACH".into());
        assert!(format!("{e}").contains("EHOSTUNREACH"));
        let e = FetchError::Timeout;
        assert_eq!(format!("{e}"), "request timed out");
    }
}
