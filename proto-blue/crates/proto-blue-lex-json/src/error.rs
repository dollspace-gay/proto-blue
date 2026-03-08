//! Error types for Lex JSON encoding/decoding.

use thiserror::Error;

/// Errors that can occur during JSON <-> LexValue conversion.
#[derive(Debug, Error)]
pub enum JsonError {
    #[error("JSON parse error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("Invalid CID string: {0}")]
    InvalidCid(String),
    #[error("Invalid base64 in $bytes: {0}")]
    InvalidBytes(String),
    #[error("Invalid $link value: expected string")]
    InvalidLink,
    #[error("Number is not a safe integer: {0}")]
    UnsafeInteger(String),
}
