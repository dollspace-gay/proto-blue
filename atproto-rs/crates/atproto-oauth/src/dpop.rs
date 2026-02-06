//! DPoP (Demonstrating Proof of Possession) — RFC 9449.
//!
//! Generates DPoP proof JWTs for OAuth token requests and API calls.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::OAuthError;

/// A DPoP key pair for signing proofs.
#[derive(Debug, Clone)]
pub struct DpopKey {
    /// The signing key (ES256 private key in JWK format).
    pub private_jwk: serde_json::Value,
    /// The public key (ES256 public key in JWK format).
    pub public_jwk: serde_json::Value,
}

impl DpopKey {
    /// Generate a new ES256 DPoP key pair.
    pub fn generate() -> Result<Self, OAuthError> {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let point = verifying_key.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(
            point
                .x()
                .ok_or_else(|| OAuthError::Other("missing x coordinate".into()))?,
        );
        let y = URL_SAFE_NO_PAD.encode(
            point
                .y()
                .ok_or_else(|| OAuthError::Other("missing y coordinate".into()))?,
        );
        let d = URL_SAFE_NO_PAD.encode(signing_key.to_bytes());

        let public_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        });

        let private_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "d": d,
        });

        Ok(DpopKey {
            private_jwk,
            public_jwk,
        })
    }
}

/// Build a DPoP proof JWT.
///
/// Parameters:
/// - `key`: The DPoP signing key
/// - `htm`: HTTP method (e.g. "POST")
/// - `htu`: HTTP URI (without query/fragment)
/// - `nonce`: Optional server-provided DPoP-Nonce
/// - `access_token`: Optional access token for `ath` claim
pub fn build_dpop_proof(
    key: &DpopKey,
    htm: &str,
    htu: &str,
    nonce: Option<&str>,
    access_token: Option<&str>,
) -> Result<String, OAuthError> {
    // Generate jti (random nonce)
    let mut jti_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut jti_bytes);
    let jti = URL_SAFE_NO_PAD.encode(jti_bytes);

    let iat = chrono::Utc::now().timestamp();

    // Build payload
    let mut payload = serde_json::json!({
        "jti": jti,
        "htm": htm,
        "htu": htu,
        "iat": iat,
    });

    if let Some(nonce) = nonce {
        payload["nonce"] = serde_json::Value::String(nonce.to_string());
    }

    // ath = base64url(SHA256(access_token))
    if let Some(token) = access_token {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let hash = hasher.finalize();
        payload["ath"] = serde_json::Value::String(URL_SAFE_NO_PAD.encode(hash));
    }

    // Extract the private key bytes from JWK
    let d_b64 = key
        .private_jwk
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::Other("Missing 'd' in private JWK".into()))?;
    let d_bytes = URL_SAFE_NO_PAD
        .decode(d_b64)
        .map_err(|e| OAuthError::Other(format!("Invalid base64 in 'd': {e}")))?;

    // Build JWT manually: header.payload.signature
    let header_json = serde_json::json!({
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": key.public_jwk,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_json)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Sign with ES256 (P-256 + SHA-256)
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    let signing_key = SigningKey::from_bytes(d_bytes.as_slice().into())
        .map_err(|e| OAuthError::Other(format!("Invalid P-256 key: {e}")))?;
    let signature: Signature = signing_key.sign(signing_input.as_bytes());

    // ES256 signatures need to be in raw r||s format (not DER)
    let sig_bytes = signature.to_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Generate a random nonce string.
pub fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_dpop_key() {
        let key = DpopKey::generate().unwrap();
        assert_eq!(key.public_jwk["kty"], "EC");
        assert_eq!(key.public_jwk["crv"], "P-256");
        assert!(key.public_jwk.get("x").is_some());
        assert!(key.public_jwk.get("y").is_some());
        assert!(key.public_jwk.get("d").is_none()); // public key has no d
        assert!(key.private_jwk.get("d").is_some()); // private key has d
    }

    #[test]
    fn build_proof_basic() {
        let key = DpopKey::generate().unwrap();
        let proof =
            build_dpop_proof(&key, "POST", "https://bsky.social/oauth/token", None, None).unwrap();

        // JWT has 3 parts
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode header
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "dpop+jwt");
        assert!(header.get("jwk").is_some());

        // Decode payload
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["htm"], "POST");
        assert_eq!(payload["htu"], "https://bsky.social/oauth/token");
        assert!(payload.get("jti").is_some());
        assert!(payload.get("iat").is_some());
    }

    #[test]
    fn build_proof_with_nonce() {
        let key = DpopKey::generate().unwrap();
        let proof = build_dpop_proof(
            &key,
            "GET",
            "https://bsky.social/xrpc/app.bsky.feed.getTimeline",
            Some("server-nonce-123"),
            None,
        )
        .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["nonce"], "server-nonce-123");
    }

    #[test]
    fn build_proof_with_access_token() {
        let key = DpopKey::generate().unwrap();
        let proof = build_dpop_proof(
            &key,
            "GET",
            "https://bsky.social/xrpc/test",
            None,
            Some("my-access-token"),
        )
        .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert!(payload.get("ath").is_some());

        // Verify ath is correct: base64url(SHA256("my-access-token"))
        let mut hasher = Sha256::new();
        hasher.update(b"my-access-token");
        let expected = URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert_eq!(payload["ath"], expected);
    }

    #[test]
    fn each_proof_has_unique_jti() {
        let key = DpopKey::generate().unwrap();
        let proof1 = build_dpop_proof(&key, "POST", "https://example.com", None, None).unwrap();
        let proof2 = build_dpop_proof(&key, "POST", "https://example.com", None, None).unwrap();

        let get_jti = |proof: &str| -> String {
            let parts: Vec<&str> = proof.split('.').collect();
            let bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            payload["jti"].as_str().unwrap().to_string()
        };

        assert_ne!(get_jti(&proof1), get_jti(&proof2));
    }

    #[test]
    fn generate_nonce_unique() {
        let a = generate_nonce();
        let b = generate_nonce();
        assert_ne!(a, b);
        assert!(!a.is_empty());
    }
}
