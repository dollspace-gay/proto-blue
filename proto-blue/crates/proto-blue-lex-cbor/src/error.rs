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
    /// The input successfully parses as CBOR but is **not in DAG-CBOR
    /// canonical form**. Violations include: map keys not sorted by
    /// byte-length-then-lex order, integers encoded in non-shortest
    /// form, indefinite-length arrays/maps/strings/bytes, or extra
    /// padding. A DAG-CBOR decoder is required to reject such inputs
    /// (RFC 8949 §4.2 + DAG-CBOR spec): two independent validators must
    /// agree on exactly which bytes are valid, and accepting
    /// non-canonical form silently breaks consensus for commit
    /// signatures, firehose replay, and proof verification.
    #[error(
        "input is valid CBOR but not DAG-CBOR canonical form \
         (input {input_len} bytes, canonical re-encode {canonical_len} bytes)"
    )]
    NonCanonical {
        input_len: usize,
        canonical_len: usize,
    },
    /// Encountered a CBOR tag other than 42 (the only tag DAG-CBOR
    /// defines, used for CID links).
    #[error("unknown CBOR tag {0} — only tag 42 (CID) is valid in DAG-CBOR")]
    UnknownTag(u64),
}
