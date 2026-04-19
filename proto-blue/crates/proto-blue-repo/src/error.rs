//! Error types for the repository system.

use proto_blue_lex_data::Cid;
use thiserror::Error;

/// Errors that can occur when working with repositories.
#[derive(Debug, Error)]
pub enum RepoError {
    #[error("Missing block: {0}")]
    MissingBlock(Cid),
    #[error("Missing blocks: {0:?}")]
    MissingBlocks(Vec<Cid>),
    #[error("Invalid commit: {0}")]
    InvalidCommit(String),
    #[error("Invalid MST: {0}")]
    InvalidMst(String),
    #[error("Invalid MST key: {0}")]
    InvalidMstKey(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),
    #[error("CBOR error: {0}")]
    Cbor(#[from] proto_blue_lex_cbor::CborError),
    #[error("CAR error: {0}")]
    Car(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Invalid signature on commit")]
    InvalidSignature,
    #[error("Crypto error: {0}")]
    Crypto(#[from] proto_blue_crypto::CryptoError),
    // Boxed to keep the enum (and therefore Result<T, RepoError>) small —
    // tungstenite's error type is ~136 B, which otherwise dominates every
    // Result sitting on the stack. See clippy `result_large_err`.
    #[cfg(feature = "firehose-client")]
    #[error("WebSocket error: {0}")]
    WebSocket(Box<proto_blue_ws::WsError>),
    #[cfg(feature = "firehose-client")]
    #[error("Frame decode error: {0}")]
    Frame(Box<proto_blue_ws::FrameError>),
    #[error("Firehose error frame: {error}{}",
        .message.as_ref().map(|m| format!(": {m}")).unwrap_or_default())]
    FirehoseError {
        error: String,
        message: Option<String>,
    },
}

#[cfg(feature = "firehose-client")]
impl From<proto_blue_ws::WsError> for RepoError {
    fn from(e: proto_blue_ws::WsError) -> Self {
        RepoError::WebSocket(Box::new(e))
    }
}

#[cfg(feature = "firehose-client")]
impl From<proto_blue_ws::FrameError> for RepoError {
    fn from(e: proto_blue_ws::FrameError) -> Self {
        RepoError::Frame(Box::new(e))
    }
}
