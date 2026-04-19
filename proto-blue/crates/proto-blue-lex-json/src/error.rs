//! Error types for Lex JSON encoding/decoding.

use thiserror::Error;

/// Errors that can occur during JSON <-> LexValue conversion.
///
/// Most variants are only produced in **strict** mode
/// ([`crate::LexParseOptions::strict`]); in the default lenient mode
/// the parser silently falls back to plain values instead of rejecting
/// malformed wrappers.
#[derive(Debug, Error)]
pub enum JsonError {
    /// The input string did not parse as JSON.
    #[error("JSON parse error: {0}")]
    Parse(#[from] serde_json::Error),
    /// A `$link` wrapper carried a CID string that failed to parse.
    /// Strict mode only.
    #[error("Invalid CID in $link: {0}")]
    InvalidCid(String),
    /// A `$bytes` wrapper carried a base64 string that failed to decode.
    /// Strict mode only.
    #[error("Invalid base64 in $bytes: {0}")]
    InvalidBytes(String),
    /// A `$link` wrapper was malformed (non-string value, or CID string
    /// longer than 2048 characters). Strict mode only.
    #[error("Invalid $link value: {0}")]
    InvalidLink(String),
    /// A JSON number was either non-integer or outside the i64 range
    /// that the AT Data Model supports. Strict mode only.
    ///
    /// TS uses the JS safe-integer bound (2^53 - 1); Rust uses the
    /// wider i64 bound. This matches in-range values byte-exactly; the
    /// extra range above 2^53 is rejected in strict mode to stay
    /// interop-safe with TS consumers.
    #[error("Number is not a safe integer: {0}")]
    UnsafeInteger(String),
    /// A `$type:"blob"` map was malformed (missing `ref`/`mimeType`/`size`,
    /// wrong types, etc.). Strict mode only.
    #[error("Invalid blob ref: {0}")]
    InvalidBlob(String),
    /// An object contained a `__proto__` key — a prototype-pollution
    /// vector. TS throws `TypeError`; we mirror that in strict mode.
    #[error("Invalid key: __proto__")]
    ProtoPollution,
}
