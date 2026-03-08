//! PKCE (Proof Key for Code Exchange) — RFC 7636.
//!
//! Generates S256 code challenges for OAuth authorization flows.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// PKCE challenge and verifier pair.
#[derive(Debug, Clone)]
pub struct PkceChallenge {
    /// The code verifier (random, base64url-encoded).
    pub verifier: String,
    /// The S256 challenge (SHA-256 hash of verifier, base64url-encoded).
    pub challenge: String,
    /// Always "S256".
    pub method: &'static str,
}

/// Generate a PKCE challenge/verifier pair using S256.
pub fn generate_pkce() -> PkceChallenge {
    generate_pkce_with_len(32)
}

/// Generate a PKCE challenge/verifier pair with a specific byte length (32-96).
pub fn generate_pkce_with_len(byte_length: usize) -> PkceChallenge {
    let byte_length = byte_length.clamp(32, 96);

    let mut bytes = vec![0u8; byte_length];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(&bytes);

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    let challenge = URL_SAFE_NO_PAD.encode(hash);

    PkceChallenge {
        verifier,
        challenge,
        method: "S256",
    }
}

/// Verify that a code_verifier matches a code_challenge using S256.
pub fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    let computed = URL_SAFE_NO_PAD.encode(hash);
    computed == challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_verify() {
        let pkce = generate_pkce();
        assert_eq!(pkce.method, "S256");
        assert!(!pkce.verifier.is_empty());
        assert!(!pkce.challenge.is_empty());
        assert_ne!(pkce.verifier, pkce.challenge);
        assert!(verify_pkce(&pkce.verifier, &pkce.challenge));
    }

    #[test]
    fn wrong_verifier_fails() {
        let pkce = generate_pkce();
        assert!(!verify_pkce("wrong_verifier", &pkce.challenge));
    }

    #[test]
    fn each_generation_is_unique() {
        let a = generate_pkce();
        let b = generate_pkce();
        assert_ne!(a.verifier, b.verifier);
        assert_ne!(a.challenge, b.challenge);
    }

    #[test]
    fn custom_byte_length() {
        let pkce = generate_pkce_with_len(64);
        assert!(verify_pkce(&pkce.verifier, &pkce.challenge));
        // 64 bytes base64url → ~86 chars
        assert!(pkce.verifier.len() > 80);
    }

    #[test]
    fn clamps_to_valid_range() {
        let small = generate_pkce_with_len(1);
        assert!(verify_pkce(&small.verifier, &small.challenge));
        // Should clamp to 32 bytes → ~43 chars
        assert!(small.verifier.len() >= 40);

        let large = generate_pkce_with_len(200);
        assert!(verify_pkce(&large.verifier, &large.challenge));
        // Should clamp to 96 bytes → ~128 chars
        assert!(large.verifier.len() <= 130);
    }

    #[test]
    fn known_vector_s256() {
        // Manually compute: verifier "test_verifier" → SHA256 → base64url
        let verifier = "test_verifier";
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hash = hasher.finalize();
        let expected = URL_SAFE_NO_PAD.encode(hash);
        assert!(verify_pkce(verifier, &expected));
    }
}
