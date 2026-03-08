//! Identity resolution error types.

/// Errors that can occur during identity resolution.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("Could not resolve DID: {0}")]
    DidNotFound(String),

    #[error("Poorly formatted DID: {0}")]
    PoorlyFormattedDid(String),

    #[error("Unsupported DID method: {0}")]
    UnsupportedDidMethod(String),

    #[error("Poorly formatted DID document for {did}")]
    PoorlyFormattedDidDocument { did: String },

    #[error("Unsupported did:web path: {0}")]
    UnsupportedDidWebPath(String),

    #[error("Could not parse signing key from DID document: {0}")]
    MissingSigningKey(String),

    #[error("Could not parse handle from DID document: {0}")]
    MissingHandle(String),

    #[error("Could not parse PDS endpoint from DID document: {0}")]
    MissingPds(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Timeout")]
    Timeout,

    #[error("{0}")]
    Other(String),
}
