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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_invalid_key() {
        let err = CryptoError::InvalidKey("bad key data".into());
        assert_eq!(err.to_string(), "Invalid key: bad key data");
    }

    #[test]
    fn display_signing_failed() {
        let err = CryptoError::SigningFailed("internal error".into());
        assert_eq!(err.to_string(), "Signing failed: internal error");
    }

    #[test]
    fn display_verification_failed() {
        let err = CryptoError::VerificationFailed("corrupt signature".into());
        assert_eq!(err.to_string(), "Verification failed: corrupt signature");
    }

    #[test]
    fn display_unsupported_algorithm() {
        let err = CryptoError::UnsupportedAlgorithm("RS512".into());
        assert_eq!(err.to_string(), "Unsupported algorithm: RS512");
    }

    #[test]
    fn display_invalid_did_key() {
        let err = CryptoError::InvalidDidKey("missing prefix".into());
        assert_eq!(err.to_string(), "Invalid DID key: missing prefix");
    }

    #[test]
    fn display_invalid_multikey() {
        let err = CryptoError::InvalidMultikey("wrong length".into());
        assert_eq!(err.to_string(), "Invalid multikey: wrong length");
    }

    #[test]
    fn display_decode_error() {
        let err = CryptoError::DecodeError("bad base58".into());
        assert_eq!(err.to_string(), "Decode error: bad base58");
    }

    #[test]
    fn clone_preserves_variant_and_message() {
        let err = CryptoError::InvalidKey("test key".into());
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    #[test]
    fn clone_all_variants() {
        let variants: Vec<CryptoError> = vec![
            CryptoError::InvalidKey("a".into()),
            CryptoError::SigningFailed("b".into()),
            CryptoError::VerificationFailed("c".into()),
            CryptoError::UnsupportedAlgorithm("d".into()),
            CryptoError::InvalidDidKey("e".into()),
            CryptoError::InvalidMultikey("f".into()),
            CryptoError::DecodeError("g".into()),
        ];
        for err in &variants {
            let cloned = err.clone();
            assert_eq!(err.to_string(), cloned.to_string());
        }
    }

    #[test]
    fn debug_formatting() {
        let err = CryptoError::InvalidKey("test".into());
        let debug = format!("{err:?}");
        assert!(
            debug.contains("InvalidKey"),
            "Debug output should contain variant name, got: {debug}"
        );
        assert!(
            debug.contains("test"),
            "Debug output should contain inner message, got: {debug}"
        );
    }

    #[test]
    fn debug_all_variants() {
        let variants: Vec<(&str, CryptoError)> = vec![
            ("InvalidKey", CryptoError::InvalidKey("x".into())),
            ("SigningFailed", CryptoError::SigningFailed("x".into())),
            (
                "VerificationFailed",
                CryptoError::VerificationFailed("x".into()),
            ),
            (
                "UnsupportedAlgorithm",
                CryptoError::UnsupportedAlgorithm("x".into()),
            ),
            ("InvalidDidKey", CryptoError::InvalidDidKey("x".into())),
            ("InvalidMultikey", CryptoError::InvalidMultikey("x".into())),
            ("DecodeError", CryptoError::DecodeError("x".into())),
        ];
        for (name, err) in &variants {
            let debug = format!("{err:?}");
            assert!(
                debug.contains(name),
                "Debug for {name} should contain variant name, got: {debug}"
            );
        }
    }
}
