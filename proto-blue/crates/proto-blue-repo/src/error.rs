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
}
