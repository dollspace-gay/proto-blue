//! Error types for cryptographic operations.

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("Invalid DID key: {0}")]
    InvalidDidKey(String),
    #[error("Invalid multikey: {0}")]
    InvalidMultikey(String),
    #[error("Decode error: {0}")]
    DecodeError(String),
}
