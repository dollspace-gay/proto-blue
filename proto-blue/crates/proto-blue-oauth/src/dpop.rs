//! `DPoP` (Demonstrating Proof of Possession) — RFC 9449.
//!
//! Generates `DPoP` proof JWTs for OAuth token requests and API calls.
//!
//! Supported algorithms:
//! - `ES256` — ECDSA over NIST P-256 + SHA-256 (the OAuth default).
//! - `ES256K` — ECDSA over secp256k1 + SHA-256 (RFC 8812). Required for
//!   atproto accounts that hold a secp256k1 key, which is a supported
//!   atproto option alongside P-256.
//!
//! The JWS signing conventions (RFC 7515 §5) hash the base64url(header).
//! base64url(payload) string once with SHA-256 and feed the digest to
//! ECDSA. Both the `p256` and `k256` crates' `Signer::sign(msg)`
//! implementations already perform that single hash internally, so the
//! signing input is passed as raw bytes (do NOT pre-hash here, or the
//! result would be SHA-256(SHA-256(input)) and reject on the server).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::OAuthError;

/// Supported `DPoP` signing algorithms.
///
/// These are the two `alg` values that atproto's OAuth spec permits; the
/// rest of the JOSE zoo (RSA, `EdDSA`, etc.) is not applicable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpopAlg {
    /// ECDSA over NIST P-256 + SHA-256.
    Es256,
    /// ECDSA over secp256k1 + SHA-256 (RFC 8812).
    Es256k,
}

impl DpopAlg {
    /// The `alg` string used in the JWT header.
    #[must_use]
    pub const fn header_alg(&self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es256k => "ES256K",
        }
    }

    /// The JWK `crv` value for this curve.
    #[must_use]
    pub const fn jwk_crv(&self) -> &'static str {
        match self {
            Self::Es256 => "P-256",
            Self::Es256k => "secp256k1",
        }
    }
}

/// A `DPoP` key pair for signing proofs.
///
/// Carries the curve in `alg` so `build_dpop_proof` can dispatch to the
/// right signing routine without re-inferring it from the JWK.
#[derive(Debug, Clone)]
pub struct DpopKey {
    /// Algorithm (ES256 or ES256K).
    pub alg: DpopAlg,
    /// The signing key (private key in JWK format).
    pub private_jwk: serde_json::Value,
    /// The public key (public-only JWK; safe to embed in the `DPoP` header).
    pub public_jwk: serde_json::Value,
}

impl DpopKey {
    /// Generate a new ES256 `DPoP` key pair (P-256). This is the default
    /// for most atproto accounts today.
    pub fn generate() -> Result<Self, OAuthError> {
        Self::generate_es256()
    }

    /// Generate a new ES256 (P-256) `DPoP` key pair.
    pub fn generate_es256() -> Result<Self, OAuthError> {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x_bytes = point
            .x()
            .ok_or_else(|| OAuthError::Other("missing x coordinate".into()))?;
        let y_bytes = point
            .y()
            .ok_or_else(|| OAuthError::Other("missing y coordinate".into()))?;

        let d_bytes = signing_key.to_bytes();
        Ok(Self::build_jwks(
            DpopAlg::Es256,
            x_bytes,
            y_bytes,
            &d_bytes[..],
        ))
    }

    /// Generate a new ES256K (secp256k1) `DPoP` key pair.
    ///
    /// Use this when the account's signing key is secp256k1 (the
    /// alternative to P-256 in atproto). The JWK `crv` field is
    /// `"secp256k1"` per RFC 8812.
    pub fn generate_es256k() -> Result<Self, OAuthError> {
        use k256::ecdsa::SigningKey;
        use k256::elliptic_curve::rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x_bytes = point
            .x()
            .ok_or_else(|| OAuthError::Other("missing x coordinate".into()))?;
        let y_bytes = point
            .y()
            .ok_or_else(|| OAuthError::Other("missing y coordinate".into()))?;

        let d_bytes = signing_key.to_bytes();
        Ok(Self::build_jwks(
            DpopAlg::Es256k,
            x_bytes,
            y_bytes,
            &d_bytes[..],
        ))
    }

    /// Shared JWK construction for both curves — the only differences
    /// between ES256 and ES256K JWKs are the `crv` value and the
    /// underlying scalar size (both are 32 bytes here, but the constant
    /// lives on the curve type).
    fn build_jwks(alg: DpopAlg, x: &[u8], y: &[u8], d: &[u8]) -> Self {
        let x_b64 = URL_SAFE_NO_PAD.encode(x);
        let y_b64 = URL_SAFE_NO_PAD.encode(y);
        let d_b64 = URL_SAFE_NO_PAD.encode(d);

        let public_jwk = serde_json::json!({
            "kty": "EC",
            "crv": alg.jwk_crv(),
            "x": x_b64,
            "y": y_b64,
        });
        let private_jwk = serde_json::json!({
            "kty": "EC",
            "crv": alg.jwk_crv(),
            "x": x_b64,
            "y": y_b64,
            "d": d_b64,
        });

        Self {
            alg,
            private_jwk,
            public_jwk,
        }
    }
}

/// Build a `DPoP` proof JWT.
///
/// Parameters:
/// - `key`: The `DPoP` signing key (any supported `DpopAlg`)
/// - `htm`: HTTP method (e.g. `"POST"`)
/// - `htu`: HTTP URI (without query/fragment)
/// - `nonce`: Optional server-provided `DPoP-Nonce`
/// - `access_token`: Optional access token for the `ath` claim
pub fn build_dpop_proof(
    key: &DpopKey,
    htm: &str,
    htu: &str,
    nonce: Option<&str>,
    access_token: Option<&str>,
) -> Result<String, OAuthError> {
    // Unique jti per RFC 9449 §4.1.
    let mut jti_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut jti_bytes);
    let jti = URL_SAFE_NO_PAD.encode(jti_bytes);

    let iat = chrono::Utc::now().timestamp();

    let mut payload = serde_json::json!({
        "jti": jti,
        "htm": htm,
        "htu": htu,
        "iat": iat,
    });
    if let Some(nonce) = nonce {
        payload["nonce"] = serde_json::Value::String(nonce.to_string());
    }
    if let Some(token) = access_token {
        // ath = base64url(SHA-256(access_token))
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let hash = hasher.finalize();
        payload["ath"] = serde_json::Value::String(URL_SAFE_NO_PAD.encode(hash));
    }

    // Extract the private key bytes from the JWK.
    let d_b64 = key
        .private_jwk
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::Other("Missing 'd' in private JWK".into()))?;
    let d_bytes = URL_SAFE_NO_PAD
        .decode(d_b64)
        .map_err(|e| OAuthError::Other(format!("Invalid base64 in 'd': {e}")))?;

    // Header embeds `alg` (curve-specific), `typ: dpop+jwt`, and the
    // full public JWK (so servers can verify without out-of-band key
    // discovery).
    let header_json = serde_json::json!({
        "alg": key.alg.header_alg(),
        "typ": "dpop+jwt",
        "jwk": key.public_jwk,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_json)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Sign with the right curve. JWS requires raw r||s (64 bytes), not DER.
    // `SigningKey::sign(msg)` internally SHA-256's the message, which is
    // what JWS wants — do not pre-hash here.
    let sig_bytes: Vec<u8> = match key.alg {
        DpopAlg::Es256 => {
            use p256::ecdsa::{Signature, SigningKey, signature::Signer};
            let signing_key = SigningKey::from_bytes(d_bytes.as_slice().into())
                .map_err(|e| OAuthError::Other(format!("Invalid P-256 key: {e}")))?;
            let signature: Signature = signing_key.sign(signing_input.as_bytes());
            signature.to_bytes().to_vec()
        }
        DpopAlg::Es256k => {
            use k256::ecdsa::{Signature, SigningKey, signature::Signer};
            let signing_key = SigningKey::from_bytes(d_bytes.as_slice().into())
                .map_err(|e| OAuthError::Other(format!("Invalid secp256k1 key: {e}")))?;
            let signature: Signature = signing_key.sign(signing_input.as_bytes());
            signature.to_bytes().to_vec()
        }
    };
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Generate a random nonce string (128 bits of entropy, base64url-encoded).
#[must_use]
pub fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ES256 (existing behavior preserved) ─────────────────────────

    #[test]
    fn generate_dpop_key_es256() {
        let key = DpopKey::generate_es256().unwrap();
        assert_eq!(key.alg, DpopAlg::Es256);
        assert_eq!(key.public_jwk["kty"], "EC");
        assert_eq!(key.public_jwk["crv"], "P-256");
        assert!(key.public_jwk.get("x").is_some());
        assert!(key.public_jwk.get("y").is_some());
        assert!(key.public_jwk.get("d").is_none());
        assert!(key.private_jwk.get("d").is_some());
    }

    #[test]
    fn generate_defaults_to_es256() {
        let key = DpopKey::generate().unwrap();
        assert_eq!(key.alg, DpopAlg::Es256);
    }

    #[test]
    fn build_proof_basic_es256() {
        let key = DpopKey::generate_es256().unwrap();
        let proof =
            build_dpop_proof(&key, "POST", "https://bsky.social/oauth/token", None, None).unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["jwk"]["crv"], "P-256");

        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["htm"], "POST");
        assert_eq!(payload["htu"], "https://bsky.social/oauth/token");
    }

    #[test]
    fn build_proof_with_nonce() {
        let key = DpopKey::generate_es256().unwrap();
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
        let key = DpopKey::generate_es256().unwrap();
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

        let mut hasher = Sha256::new();
        hasher.update(b"my-access-token");
        let expected = URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert_eq!(payload["ath"], expected);
    }

    #[test]
    fn each_proof_has_unique_jti() {
        let key = DpopKey::generate_es256().unwrap();
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

    // ── ES256K (new, issue #8) ──────────────────────────────────────

    #[test]
    fn generate_dpop_key_es256k_has_secp256k1_jwk() {
        let key = DpopKey::generate_es256k().unwrap();
        assert_eq!(key.alg, DpopAlg::Es256k);
        assert_eq!(key.public_jwk["kty"], "EC");
        assert_eq!(key.public_jwk["crv"], "secp256k1");
        assert!(key.public_jwk.get("x").is_some());
        assert!(key.public_jwk.get("y").is_some());
        assert!(key.public_jwk.get("d").is_none());
        assert!(key.private_jwk.get("d").is_some());
    }

    #[test]
    fn build_proof_es256k_uses_correct_header_alg_and_jwk() {
        let key = DpopKey::generate_es256k().unwrap();
        let proof = build_dpop_proof(
            &key,
            "POST",
            "https://pds.example.com/oauth/token",
            None,
            None,
        )
        .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256K");
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["jwk"]["crv"], "secp256k1");
    }

    /// End-to-end: an ES256K proof must verify against the k256 library
    /// when the server extracts the jwk from the header. This proves the
    /// public JWK in the header and the signature are consistent.
    #[test]
    fn es256k_proof_verifies_with_embedded_public_jwk() {
        use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        use k256::elliptic_curve::sec1::EncodedPoint;

        let key = DpopKey::generate_es256k().unwrap();
        let proof = build_dpop_proof(&key, "POST", "https://example.com", None, None).unwrap();
        let parts: Vec<&str> = proof.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        // Reconstruct the public key from the embedded JWK.
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        let x = URL_SAFE_NO_PAD
            .decode(header["jwk"]["x"].as_str().unwrap())
            .unwrap();
        let y = URL_SAFE_NO_PAD
            .decode(header["jwk"]["y"].as_str().unwrap())
            .unwrap();
        let point = EncodedPoint::<k256::Secp256k1>::from_affine_coordinates(
            x.as_slice().into(),
            y.as_slice().into(),
            false,
        );
        let verifying_key = VerifyingKey::from_encoded_point(&point).unwrap();

        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();

        assert!(
            verifying_key.verify(signing_input.as_bytes(), &sig).is_ok(),
            "ES256K DPoP proof signature must verify with its own embedded jwk"
        );
    }

    /// Same end-to-end check for ES256 (P-256) — ensures the refactor
    /// didn't break existing behavior.
    #[test]
    fn es256_proof_verifies_with_embedded_public_jwk() {
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        use p256::elliptic_curve::sec1::EncodedPoint;

        let key = DpopKey::generate_es256().unwrap();
        let proof = build_dpop_proof(&key, "POST", "https://example.com", None, None).unwrap();
        let parts: Vec<&str> = proof.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        let x = URL_SAFE_NO_PAD
            .decode(header["jwk"]["x"].as_str().unwrap())
            .unwrap();
        let y = URL_SAFE_NO_PAD
            .decode(header["jwk"]["y"].as_str().unwrap())
            .unwrap();
        let point = EncodedPoint::<p256::NistP256>::from_affine_coordinates(
            x.as_slice().into(),
            y.as_slice().into(),
            false,
        );
        let verifying_key = VerifyingKey::from_encoded_point(&point).unwrap();

        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        assert!(verifying_key.verify(signing_input.as_bytes(), &sig).is_ok());
    }
}
