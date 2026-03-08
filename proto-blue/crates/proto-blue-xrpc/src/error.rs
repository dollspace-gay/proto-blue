//! XRPC error types and response codes.

use std::fmt;

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
    /// Convert an HTTP status code to a ResponseType.
    pub fn from_http_status(status: u16) -> Self {
        match status {
            200 => ResponseType::Success,
            400 => ResponseType::InvalidRequest,
            401 => ResponseType::AuthenticationRequired,
            403 => ResponseType::Forbidden,
            404 => ResponseType::XRPCNotSupported,
            406 => ResponseType::NotAcceptable,
            413 => ResponseType::PayloadTooLarge,
            415 => ResponseType::UnsupportedMediaType,
            429 => ResponseType::RateLimitExceeded,
            500 => ResponseType::InternalServerError,
            501 => ResponseType::MethodNotImplemented,
            502 => ResponseType::UpstreamFailure,
            503 => ResponseType::NotEnoughResources,
            504 => ResponseType::UpstreamTimeout,
            s if (200..300).contains(&s) => ResponseType::Success,
            s if (400..500).contains(&s) => ResponseType::InvalidRequest,
            s if s >= 500 => ResponseType::InternalServerError,
            _ => ResponseType::XRPCNotSupported,
        }
    }

    /// Human-readable name for the response type.
    pub fn name(&self) -> &'static str {
        match self {
            ResponseType::Unknown => "Unknown",
            ResponseType::InvalidResponse => "Invalid Response",
            ResponseType::Success => "Success",
            ResponseType::InvalidRequest => "Invalid Request",
            ResponseType::AuthenticationRequired => "Authentication Required",
            ResponseType::Forbidden => "Forbidden",
            ResponseType::XRPCNotSupported => "XRPC Not Supported",
            ResponseType::NotAcceptable => "Not Acceptable",
            ResponseType::PayloadTooLarge => "Payload Too Large",
            ResponseType::UnsupportedMediaType => "Unsupported Media Type",
            ResponseType::RateLimitExceeded => "Rate Limit Exceeded",
            ResponseType::InternalServerError => "Internal Server Error",
            ResponseType::MethodNotImplemented => "Method Not Implemented",
            ResponseType::UpstreamFailure => "Upstream Failure",
            ResponseType::NotEnoughResources => "Not Enough Resources",
            ResponseType::UpstreamTimeout => "Upstream Timeout",
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
    /// Machine-readable error code from the server (e.g. "InvalidToken").
    pub error: Option<String>,
    /// Human-readable error message.
    pub message: Option<String>,
    /// Response headers (if available).
    pub headers: Option<std::collections::HashMap<String, String>>,
}

impl fmt::Display for XrpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(msg) = &self.message {
            write!(f, "{}", msg)
        } else if let Some(err) = &self.error {
            write!(f, "{}", err)
        } else {
            write!(f, "{}", self.status)
        }
    }
}

impl XrpcError {
    /// Create a new XrpcError from an HTTP status code.
    pub fn from_status(status_code: u16, error: Option<String>, message: Option<String>) -> Self {
        XrpcError {
            status: ResponseType::from_http_status(status_code),
            error,
            message,
            headers: None,
        }
    }

    /// Create a new XrpcError with the given ResponseType.
    pub fn new(status: ResponseType, message: impl Into<String>) -> Self {
        XrpcError {
            status,
            error: Some(status.name().to_string()),
            message: Some(message.into()),
            headers: None,
        }
    }

    /// Check if this error matches a specific error string.
    pub fn is_error(&self, error_name: &str) -> bool {
        self.error.as_deref() == Some(error_name)
    }
}

/// Errors that can occur during XRPC operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("XRPC error: {0}")]
    Xrpc(#[from] XrpcError),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}
