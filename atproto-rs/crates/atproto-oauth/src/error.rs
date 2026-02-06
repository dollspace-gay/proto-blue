//! OAuth error types.

use thiserror::Error;

/// Errors from the OAuth 2.0 flow.
#[derive(Debug, Error)]
pub enum OAuthError {
    /// HTTP request failed.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// URL parsing failed.
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),

    /// The authorization server returned an error.
    #[error("OAuth server error: {error} - {error_description}")]
    ServerError {
        error: String,
        error_description: String,
    },

    /// Token refresh failed.
    #[error("Token refresh failed: {0}")]
    RefreshFailed(String),

    /// The session is not authenticated.
    #[error("Not authenticated")]
    NotAuthenticated,

    /// PKCE verification failed.
    #[error("PKCE verification failed")]
    PkceVerificationFailed,

    /// DPoP nonce was required but not provided.
    #[error("DPoP nonce required: {0}")]
    DpopNonceRequired(String),

    /// Invalid state parameter in callback.
    #[error("Invalid state parameter")]
    InvalidState,

    /// The issuer doesn't match expectations.
    #[error("Issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },

    /// Missing required field.
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Catch-all for other errors.
    #[error("{0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let e = OAuthError::NotAuthenticated;
        assert_eq!(e.to_string(), "Not authenticated");

        let e = OAuthError::ServerError {
            error: "invalid_grant".into(),
            error_description: "Token expired".into(),
        };
        assert!(e.to_string().contains("invalid_grant"));
    }

    #[test]
    fn error_from_json() {
        let result: Result<serde_json::Value, _> = serde_json::from_str("invalid");
        let err: OAuthError = result.unwrap_err().into();
        assert!(matches!(err, OAuthError::Json(_)));
    }

    #[test]
    fn error_from_url() {
        let result: Result<url::Url, _> = url::Url::parse("not a url");
        let err: OAuthError = result.unwrap_err().into();
        assert!(matches!(err, OAuthError::Url(_)));
    }
}
