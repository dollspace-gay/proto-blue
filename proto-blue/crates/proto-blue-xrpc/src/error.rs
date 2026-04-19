//! XRPC error types and response codes.

use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};

/// XRPC response type codes, matching the AT Protocol specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ResponseType {
    /// Network issue, unable to get response from the server.
    Unknown = 1,
    /// Response failed lexicon validation.
    InvalidResponse = 2,
    Success = 200,
    InvalidRequest = 400,
    AuthenticationRequired = 401,
    Forbidden = 403,
    XRPCNotSupported = 404,
    NotAcceptable = 406,
    PayloadTooLarge = 413,
    UnsupportedMediaType = 415,
    RateLimitExceeded = 429,
    InternalServerError = 500,
    MethodNotImplemented = 501,
    UpstreamFailure = 502,
    NotEnoughResources = 503,
    UpstreamTimeout = 504,
}

impl ResponseType {
    /// Convert an HTTP status code to a `ResponseType`.
    #[must_use]
    pub fn from_http_status(status: u16) -> Self {
        match status {
            200 => Self::Success,
            400 => Self::InvalidRequest,
            401 => Self::AuthenticationRequired,
            403 => Self::Forbidden,
            404 => Self::XRPCNotSupported,
            406 => Self::NotAcceptable,
            413 => Self::PayloadTooLarge,
            415 => Self::UnsupportedMediaType,
            429 => Self::RateLimitExceeded,
            500 => Self::InternalServerError,
            501 => Self::MethodNotImplemented,
            502 => Self::UpstreamFailure,
            503 => Self::NotEnoughResources,
            504 => Self::UpstreamTimeout,
            s if (200..300).contains(&s) => Self::Success,
            s if (400..500).contains(&s) => Self::InvalidRequest,
            s if s >= 500 => Self::InternalServerError,
            _ => Self::XRPCNotSupported,
        }
    }

    /// Human-readable name for the response type.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::InvalidResponse => "Invalid Response",
            Self::Success => "Success",
            Self::InvalidRequest => "Invalid Request",
            Self::AuthenticationRequired => "Authentication Required",
            Self::Forbidden => "Forbidden",
            Self::XRPCNotSupported => "XRPC Not Supported",
            Self::NotAcceptable => "Not Acceptable",
            Self::PayloadTooLarge => "Payload Too Large",
            Self::UnsupportedMediaType => "Unsupported Media Type",
            Self::RateLimitExceeded => "Rate Limit Exceeded",
            Self::InternalServerError => "Internal Server Error",
            Self::MethodNotImplemented => "Method Not Implemented",
            Self::UpstreamFailure => "Upstream Failure",
            Self::NotEnoughResources => "Not Enough Resources",
            Self::UpstreamTimeout => "Upstream Timeout",
        }
    }
}

impl fmt::Display for ResponseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// XRPC error returned by client operations.
#[derive(Debug, thiserror::Error)]
pub struct XrpcError {
    /// Response type / status category.
    pub status: ResponseType,
    /// Machine-readable error code from the server (e.g. "`InvalidToken`").
    pub error: Option<String>,
    /// Human-readable error message.
    pub message: Option<String>,
    /// Response headers (if available).
    pub headers: Option<std::collections::HashMap<String, String>>,
}

impl fmt::Display for XrpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(msg) = &self.message {
            write!(f, "{msg}")
        } else if let Some(err) = &self.error {
            write!(f, "{err}")
        } else {
            write!(f, "{}", self.status)
        }
    }
}

impl XrpcError {
    /// Create a new `XrpcError` from an HTTP status code.
    #[must_use]
    pub fn from_status(status_code: u16, error: Option<String>, message: Option<String>) -> Self {
        Self {
            status: ResponseType::from_http_status(status_code),
            error,
            message,
            headers: None,
        }
    }

    /// Create a new `XrpcError` with the given `ResponseType`.
    pub fn new(status: ResponseType, message: impl Into<String>) -> Self {
        Self {
            status,
            error: Some(status.name().to_string()),
            message: Some(message.into()),
            headers: None,
        }
    }

    /// Check if this error matches a specific error string.
    #[must_use]
    pub fn is_error(&self, error_name: &str) -> bool {
        self.error.as_deref() == Some(error_name)
    }

    /// Parse the `Retry-After` response header, if present.
    ///
    /// Per RFC 7231 §7.1.3 the value is either:
    /// - a non-negative integer number of seconds (`Retry-After: 120`), or
    /// - an HTTP-date (`Retry-After: Fri, 31 Dec 2025 23:59:59 GMT`).
    ///
    /// Returns `None` if the header is absent, malformed, or points to the
    /// past. For an HTTP-date the duration is measured from "now" (i.e.
    /// `header_time - Utc::now()`, clamped at zero).
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        let raw = self.header("retry-after")?;

        // Integer seconds form.
        if let Ok(secs) = raw.parse::<u64>() {
            return Some(Duration::from_secs(secs));
        }

        // HTTP-date form. chrono's RFC 2822 parser handles the IMF-fixdate
        // variant (`Fri, 31 Dec 2025 23:59:59 GMT`) that RFC 7231 mandates.
        let parsed = DateTime::parse_from_rfc2822(raw).ok()?;
        let now = Utc::now();
        let delta = parsed.with_timezone(&Utc).signed_duration_since(now);
        delta.to_std().ok()
    }

    /// Parse the draft `RateLimit-*` headers, if all three are present.
    ///
    /// Returns `None` unless `RateLimit-Limit`, `RateLimit-Remaining`, and
    /// `RateLimit-Reset` are all set and parseable. atproto emits an
    /// absolute Unix timestamp (seconds) in `RateLimit-Reset`; we expose it
    /// as a `DateTime<Utc>` so callers don't have to reconstruct the time
    /// base from a relative number.
    #[must_use]
    pub fn rate_limit(&self) -> Option<RateLimit> {
        let limit: u64 = self.header("ratelimit-limit")?.parse().ok()?;
        let remaining: u64 = self.header("ratelimit-remaining")?.parse().ok()?;
        let reset_secs: i64 = self.header("ratelimit-reset")?.parse().ok()?;
        let reset = DateTime::<Utc>::from_timestamp(reset_secs, 0)?;
        Some(RateLimit {
            limit,
            remaining,
            reset,
        })
    }

    /// Case-insensitive header lookup. Our header map is populated with
    /// lowercased keys by `handle_response`, so we just lowercase the query.
    fn header(&self, name: &str) -> Option<&str> {
        let needle = name.to_ascii_lowercase();
        self.headers.as_ref()?.get(&needle).map(String::as_str)
    }
}

/// Parsed draft `RateLimit-*` response headers.
///
/// See the IETF draft "`RateLimit` Fields for HTTP"
/// (<https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/>)
/// and atproto's use of the same fields in PDS responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimit {
    /// The rate-limit quota (total allowed requests in the current window).
    pub limit: u64,
    /// Requests remaining in the current window.
    pub remaining: u64,
    /// Absolute time at which the quota resets.
    pub reset: DateTime<Utc>,
}

/// Errors that can occur during XRPC operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("XRPC error: {0}")]
    Xrpc(#[from] XrpcError),

    /// Transport-level failure from the configured [`FetchHandler`].
    ///
    /// [`FetchHandler`]: proto_blue_common::fetch::FetchHandler
    #[error("fetch error: {0}")]
    Fetch(#[from] proto_blue_common::fetch::FetchError),

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The call was cancelled via [`crate::CallOptions::cancel`]. The
    /// in-flight fetch was dropped before the response arrived.
    #[error("call was cancelled")]
    Cancelled,

    /// The response body exceeded the configured maximum
    /// ([`crate::CallOptions::max_response_bytes`]).
    #[error("response body exceeded {limit} bytes (got {got})")]
    ResponseTooLarge { limit: usize, got: usize },

    /// The response body failed lexicon validation
    /// ([`crate::CallOptions::validate`]).
    #[error("lexicon validation failed: {0}")]
    LexiconValidation(#[from] proto_blue_lexicon::ValidationError),

    #[error("{0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ResponseType::from_http_status() – explicit codes ────────────

    #[test]
    fn from_http_status_200() {
        assert_eq!(ResponseType::from_http_status(200), ResponseType::Success);
    }

    #[test]
    fn from_http_status_400() {
        assert_eq!(
            ResponseType::from_http_status(400),
            ResponseType::InvalidRequest
        );
    }

    #[test]
    fn from_http_status_401() {
        assert_eq!(
            ResponseType::from_http_status(401),
            ResponseType::AuthenticationRequired
        );
    }

    #[test]
    fn from_http_status_403() {
        assert_eq!(ResponseType::from_http_status(403), ResponseType::Forbidden);
    }

    #[test]
    fn from_http_status_404() {
        assert_eq!(
            ResponseType::from_http_status(404),
            ResponseType::XRPCNotSupported
        );
    }

    #[test]
    fn from_http_status_406() {
        assert_eq!(
            ResponseType::from_http_status(406),
            ResponseType::NotAcceptable
        );
    }

    #[test]
    fn from_http_status_413() {
        assert_eq!(
            ResponseType::from_http_status(413),
            ResponseType::PayloadTooLarge
        );
    }

    #[test]
    fn from_http_status_415() {
        assert_eq!(
            ResponseType::from_http_status(415),
            ResponseType::UnsupportedMediaType
        );
    }

    #[test]
    fn from_http_status_429() {
        assert_eq!(
            ResponseType::from_http_status(429),
            ResponseType::RateLimitExceeded
        );
    }

    #[test]
    fn from_http_status_500() {
        assert_eq!(
            ResponseType::from_http_status(500),
            ResponseType::InternalServerError
        );
    }

    #[test]
    fn from_http_status_501() {
        assert_eq!(
            ResponseType::from_http_status(501),
            ResponseType::MethodNotImplemented
        );
    }

    #[test]
    fn from_http_status_502() {
        assert_eq!(
            ResponseType::from_http_status(502),
            ResponseType::UpstreamFailure
        );
    }

    #[test]
    fn from_http_status_503() {
        assert_eq!(
            ResponseType::from_http_status(503),
            ResponseType::NotEnoughResources
        );
    }

    #[test]
    fn from_http_status_504() {
        assert_eq!(
            ResponseType::from_http_status(504),
            ResponseType::UpstreamTimeout
        );
    }

    // ── ResponseType::from_http_status() – range fallbacks ───────────

    #[test]
    fn from_http_status_201_maps_to_success() {
        assert_eq!(ResponseType::from_http_status(201), ResponseType::Success);
    }

    #[test]
    fn from_http_status_204_maps_to_success() {
        assert_eq!(ResponseType::from_http_status(204), ResponseType::Success);
    }

    #[test]
    fn from_http_status_450_maps_to_invalid_request() {
        assert_eq!(
            ResponseType::from_http_status(450),
            ResponseType::InvalidRequest
        );
    }

    #[test]
    fn from_http_status_499_maps_to_invalid_request() {
        assert_eq!(
            ResponseType::from_http_status(499),
            ResponseType::InvalidRequest
        );
    }

    #[test]
    fn from_http_status_550_maps_to_internal_server_error() {
        assert_eq!(
            ResponseType::from_http_status(550),
            ResponseType::InternalServerError
        );
    }

    #[test]
    fn from_http_status_599_maps_to_internal_server_error() {
        assert_eq!(
            ResponseType::from_http_status(599),
            ResponseType::InternalServerError
        );
    }

    #[test]
    fn from_http_status_100_maps_to_xrpc_not_supported() {
        // codes outside 2xx/4xx/5xx fall to the catch-all
        assert_eq!(
            ResponseType::from_http_status(100),
            ResponseType::XRPCNotSupported
        );
    }

    // ── ResponseType::name() ─────────────────────────────────────────

    #[test]
    fn name_returns_correct_strings() {
        assert_eq!(ResponseType::Unknown.name(), "Unknown");
        assert_eq!(ResponseType::InvalidResponse.name(), "Invalid Response");
        assert_eq!(ResponseType::Success.name(), "Success");
        assert_eq!(ResponseType::InvalidRequest.name(), "Invalid Request");
        assert_eq!(
            ResponseType::AuthenticationRequired.name(),
            "Authentication Required"
        );
        assert_eq!(ResponseType::Forbidden.name(), "Forbidden");
        assert_eq!(ResponseType::XRPCNotSupported.name(), "XRPC Not Supported");
        assert_eq!(ResponseType::NotAcceptable.name(), "Not Acceptable");
        assert_eq!(ResponseType::PayloadTooLarge.name(), "Payload Too Large");
        assert_eq!(
            ResponseType::UnsupportedMediaType.name(),
            "Unsupported Media Type"
        );
        assert_eq!(
            ResponseType::RateLimitExceeded.name(),
            "Rate Limit Exceeded"
        );
        assert_eq!(
            ResponseType::InternalServerError.name(),
            "Internal Server Error"
        );
        assert_eq!(
            ResponseType::MethodNotImplemented.name(),
            "Method Not Implemented"
        );
        assert_eq!(ResponseType::UpstreamFailure.name(), "Upstream Failure");
        assert_eq!(
            ResponseType::NotEnoughResources.name(),
            "Not Enough Resources"
        );
        assert_eq!(ResponseType::UpstreamTimeout.name(), "Upstream Timeout");
    }

    // ── ResponseType Display ─────────────────────────────────────────

    #[test]
    fn display_uses_name() {
        assert_eq!(format!("{}", ResponseType::Success), "Success");
        assert_eq!(format!("{}", ResponseType::Forbidden), "Forbidden");
        assert_eq!(
            format!("{}", ResponseType::InternalServerError),
            "Internal Server Error"
        );
    }

    // ── XrpcError::from_status() ─────────────────────────────────────

    #[test]
    fn xrpc_error_from_status() {
        let err = XrpcError::from_status(404, Some("NotFound".into()), Some("gone".into()));
        assert_eq!(err.status, ResponseType::XRPCNotSupported);
        assert_eq!(err.error.as_deref(), Some("NotFound"));
        assert_eq!(err.message.as_deref(), Some("gone"));
        assert!(err.headers.is_none());
    }

    #[test]
    fn xrpc_error_from_status_no_error_no_message() {
        let err = XrpcError::from_status(500, None, None);
        assert_eq!(err.status, ResponseType::InternalServerError);
        assert!(err.error.is_none());
        assert!(err.message.is_none());
    }

    // ── XrpcError::new() ─────────────────────────────────────────────

    #[test]
    fn xrpc_error_new() {
        let err = XrpcError::new(ResponseType::Forbidden, "access denied");
        assert_eq!(err.status, ResponseType::Forbidden);
        assert_eq!(err.error.as_deref(), Some("Forbidden"));
        assert_eq!(err.message.as_deref(), Some("access denied"));
        assert!(err.headers.is_none());
    }

    // ── XrpcError::is_error() ────────────────────────────────────────

    #[test]
    fn is_error_matching() {
        let err = XrpcError::from_status(401, Some("InvalidToken".into()), None);
        assert!(err.is_error("InvalidToken"));
        assert!(!err.is_error("ExpiredToken"));
    }

    #[test]
    fn is_error_when_none() {
        let err = XrpcError::from_status(500, None, None);
        assert!(!err.is_error("anything"));
    }

    // ── XrpcError Display ────────────────────────────────────────────

    #[test]
    fn display_with_message() {
        let err =
            XrpcError::from_status(400, Some("BadInput".into()), Some("invalid field".into()));
        assert_eq!(format!("{err}"), "invalid field");
    }

    #[test]
    fn display_with_error_only() {
        let err = XrpcError::from_status(400, Some("BadInput".into()), None);
        assert_eq!(format!("{err}"), "BadInput");
    }

    #[test]
    fn display_with_neither() {
        let err = XrpcError::from_status(500, None, None);
        assert_eq!(format!("{err}"), "Internal Server Error");
    }

    // ── Error enum From conversions ──────────────────────────────────

    #[test]
    fn error_from_xrpc_error() {
        let xrpc = XrpcError::new(ResponseType::Unknown, "test");
        let err: Error = xrpc.into();
        match err {
            Error::Xrpc(e) => assert_eq!(e.status, ResponseType::Unknown),
            _ => panic!("expected Xrpc variant"),
        }
    }

    #[test]
    fn error_from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err: Error = json_err.into();
        match err {
            Error::Json(_) => {} // ok
            _ => panic!("expected Json variant"),
        }
    }

    // ── Retry-After parsing ──────────────────────────────────────────

    fn err_with_header(name: &str, value: &str) -> XrpcError {
        let mut headers = std::collections::HashMap::new();
        headers.insert(name.to_ascii_lowercase(), value.to_string());
        XrpcError {
            status: ResponseType::RateLimitExceeded,
            error: None,
            message: None,
            headers: Some(headers),
        }
    }

    #[test]
    fn retry_after_seconds_form() {
        let err = err_with_header("Retry-After", "120");
        assert_eq!(err.retry_after(), Some(Duration::from_secs(120)));
    }

    #[test]
    fn retry_after_zero_seconds() {
        let err = err_with_header("Retry-After", "0");
        assert_eq!(err.retry_after(), Some(Duration::from_secs(0)));
    }

    #[test]
    fn retry_after_http_date_in_future_returns_positive_duration() {
        // Build a date ~3600 s in the future and format it RFC 2822 style.
        let future = Utc::now() + chrono::Duration::seconds(3600);
        let header_value = future.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let err = err_with_header("Retry-After", &header_value);

        let got = err.retry_after().expect("should parse");
        // Allow a generous window for test scheduling.
        assert!(got >= Duration::from_secs(3500) && got <= Duration::from_secs(3700));
    }

    #[test]
    fn retry_after_http_date_in_past_returns_none() {
        let past = Utc::now() - chrono::Duration::seconds(3600);
        let header_value = past.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let err = err_with_header("Retry-After", &header_value);
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_invalid_returns_none() {
        let err = err_with_header("Retry-After", "soon-ish");
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_missing_returns_none() {
        let err = XrpcError::from_status(429, None, None);
        assert_eq!(err.retry_after(), None);
    }

    // ── RateLimit-* parsing ──────────────────────────────────────────

    fn err_with_headers(pairs: &[(&str, &str)]) -> XrpcError {
        let mut headers = std::collections::HashMap::new();
        for (k, v) in pairs {
            headers.insert(k.to_ascii_lowercase(), v.to_string());
        }
        XrpcError {
            status: ResponseType::RateLimitExceeded,
            error: None,
            message: None,
            headers: Some(headers),
        }
    }

    #[test]
    fn rate_limit_all_three_headers_parsed() {
        let err = err_with_headers(&[
            ("RateLimit-Limit", "3000"),
            ("RateLimit-Remaining", "2998"),
            ("RateLimit-Reset", "1700000000"),
        ]);
        let rl = err.rate_limit().expect("should parse");
        assert_eq!(rl.limit, 3000);
        assert_eq!(rl.remaining, 2998);
        assert_eq!(rl.reset.timestamp(), 1_700_000_000);
    }

    #[test]
    fn rate_limit_missing_one_returns_none() {
        // Missing `RateLimit-Reset` -> not enough information -> None.
        let err = err_with_headers(&[("RateLimit-Limit", "100"), ("RateLimit-Remaining", "0")]);
        assert!(err.rate_limit().is_none());
    }

    #[test]
    fn rate_limit_non_numeric_returns_none() {
        let err = err_with_headers(&[
            ("RateLimit-Limit", "many"),
            ("RateLimit-Remaining", "0"),
            ("RateLimit-Reset", "1700000000"),
        ]);
        assert!(err.rate_limit().is_none());
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        // The map is stored lowercase; our helper must lowercase the query.
        let err = err_with_header("retry-after", "60");
        assert_eq!(err.retry_after(), Some(Duration::from_secs(60)));
    }
}
