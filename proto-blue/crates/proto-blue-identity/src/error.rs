//! Identity resolution error types.

/// Errors that can occur during identity resolution.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("Could not resolve DID: {0}")]
    DidNotFound(String),

    #[error("Could not resolve handle: {0}")]
    HandleNotFound(String),

    #[error("Handle/DID binding mismatch: DID {did} does not claim handle {handle} in alsoKnownAs")]
    HandleDidMismatch { handle: String, did: String },

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

    /// Transport-level failure from the configured [`FetchHandler`].
    ///
    /// [`FetchHandler`]: proto_blue_common::fetch::FetchHandler
    #[error("fetch error: {0}")]
    Fetch(#[from] proto_blue_common::fetch::FetchError),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Timeout")]
    Timeout,

    #[error("{0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_did_not_found() {
        let err = IdentityError::DidNotFound("did:plc:abc123".into());
        assert_eq!(err.to_string(), "Could not resolve DID: did:plc:abc123");
    }

    #[test]
    fn display_poorly_formatted_did() {
        let err = IdentityError::PoorlyFormattedDid("not-a-did".into());
        assert_eq!(err.to_string(), "Poorly formatted DID: not-a-did");
    }

    #[test]
    fn display_unsupported_did_method() {
        let err = IdentityError::UnsupportedDidMethod("did:example:123".into());
        assert_eq!(err.to_string(), "Unsupported DID method: did:example:123");
    }

    #[test]
    fn display_poorly_formatted_did_document() {
        let err = IdentityError::PoorlyFormattedDidDocument {
            did: "did:plc:bad".into(),
        };
        assert_eq!(
            err.to_string(),
            "Poorly formatted DID document for did:plc:bad"
        );
    }

    #[test]
    fn display_unsupported_did_web_path() {
        let err = IdentityError::UnsupportedDidWebPath("did:web:example.com:path".into());
        assert_eq!(
            err.to_string(),
            "Unsupported did:web path: did:web:example.com:path"
        );
    }

    #[test]
    fn display_missing_signing_key() {
        let err = IdentityError::MissingSigningKey("did:plc:nokey".into());
        assert_eq!(
            err.to_string(),
            "Could not parse signing key from DID document: did:plc:nokey"
        );
    }

    #[test]
    fn display_missing_handle() {
        let err = IdentityError::MissingHandle("did:plc:nohandle".into());
        assert_eq!(
            err.to_string(),
            "Could not parse handle from DID document: did:plc:nohandle"
        );
    }

    #[test]
    fn display_missing_pds() {
        let err = IdentityError::MissingPds("did:plc:nopds".into());
        assert_eq!(
            err.to_string(),
            "Could not parse PDS endpoint from DID document: did:plc:nopds"
        );
    }

    #[test]
    fn display_dns_error() {
        let err = IdentityError::Dns("NXDOMAIN".into());
        assert_eq!(err.to_string(), "DNS error: NXDOMAIN");
    }

    #[test]
    fn display_timeout() {
        let err = IdentityError::Timeout;
        assert_eq!(err.to_string(), "Timeout");
    }

    #[test]
    fn display_other() {
        let err = IdentityError::Other("something went wrong".into());
        assert_eq!(err.to_string(), "something went wrong");
    }

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("not valid json").unwrap_err();
        let expected_msg = format!("JSON error: {json_err}");
        let err: IdentityError = json_err.into();
        assert_eq!(err.to_string(), expected_msg);
        assert!(matches!(err, IdentityError::Json(_)));
    }
}
