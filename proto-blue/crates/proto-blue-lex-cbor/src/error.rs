//! Error types for DAG-CBOR encoding/decoding.

use thiserror::Error;

/// Errors that can occur during DAG-CBOR encoding or decoding.
#[derive(Debug, Error)]
pub enum CborError {
    #[error("CBOR encoding error: {0}")]
    Encode(String),
    #[error("CBOR decoding error: {0}")]
    Decode(String),
    #[error("Invalid CID in CBOR tag 42: {0}")]
    InvalidCid(String),
    #[error("Float values are not supported by the AT Data Model")]
    FloatNotSupported,
    #[error("Non-string map keys are not supported by the AT Data Model")]
    NonStringKey,
    #[error("Duplicate map key: {0}")]
    DuplicateKey(String),
}
