//! `private_key_jwt` client authentication (RFC 7523 §2.2).
//!
//! Confidential OAuth clients authenticate to the `/token` endpoint
//! by signing a short JWT — the "client assertion" — and sending it
//! alongside the grant in the form body:
//!
//! ```text
//! client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//! client_assertion=<compact-jws>
//! ```
//!
//! This module builds those JWTs. The signing key lives in a
//! [`ClientKeyset`] that the caller constructs up-front from whatever
//! secure storage they use (HSM, kube secret, local file, etc.). The
//! crate doesn't dictate where the key comes from, only how it gets
//! used.
//!
//! Claims per §3 of RFC 7523:
//! - `iss` = `client_id`
//! - `sub` = `client_id`
//! - `aud` = token endpoint URL (or issuer, depending on the AS; we
//!   follow the common convention and use the token endpoint since
//!   that's what atproto's reference AS expects).
//! - `jti` = 16 bytes of entropy, base64url-encoded
//! - `iat` = now (seconds)
//! - `exp` = now + 60s — intentionally tight, since this JWT is
//!   single-use at the `/token` endpoint.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;

use crate::dpop::DpopAlg;
use crate::error::OAuthError;

/// The `client_assertion_type` value required by RFC 7523.
pub const CLIENT_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A private signing key + its stable `kid` and `alg`.
///
/// Callers build this from their own key material — typically loaded
/// from a JWKS published at the client's `jwks_uri`. The `kid` is
/// included in the JWT header so the AS can look the public key up in
/// the published JWKS; it MUST match an entry in the client's
/// `jwks` / `jwks_uri` document.
#[derive(Debug, Clone)]
pub struct ClientKey {
    /// Signing algorithm (ES256 or ES256K).
    pub alg: DpopAlg,
    /// Stable key identifier. Matched against the published JWKS.
    pub kid: String,
    /// Raw private key bytes (32 bytes for both curves).
    pub d: Vec<u8>,
}

/// A keyset for `private_key_jwt`. A client publishes multiple keys
/// to support rotation; at sign time the crate picks the first key
/// whose `alg` the AS advertises support for.
#[derive(Debug, Clone, Default)]
pub struct ClientKeyset {
    pub keys: Vec<ClientKey>,
}

impl ClientKeyset {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_key(mut self, key: ClientKey) -> Self {
        self.keys.push(key);
        self
    }

    /// Select a key compatible with one of the AS-advertised algs.
    /// Returns `None` if no key in the set matches. Input strings are
    /// the JOSE `alg` names (`"ES256"`, `"ES256K"`).
    pub fn select_for(&self, supported_algs: &[String]) -> Option<&ClientKey> {
        self.keys
            .iter()
            .find(|k| supported_algs.iter().any(|a| a == k.alg.header_alg()))
    }
}

/// Build a compact-JWS `client_assertion` for `private_key_jwt` auth.
///
/// `aud` should be the token endpoint URL.
pub fn build_client_assertion(
    key: &ClientKey,
    client_id: &str,
    aud: &str,
) -> Result<String, OAuthError> {
    let mut jti_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut jti_bytes);
    let jti = URL_SAFE_NO_PAD.encode(jti_bytes);

    let iat = chrono::Utc::now().timestamp();
    let exp = iat + 60;

    let header = serde_json::json!({
        "alg": key.alg.header_alg(),
        "typ": "JWT",
        "kid": key.kid,
    });
    let payload = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": aud,
        "jti": jti,
        "iat": iat,
        "exp": exp,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let sig_bytes: Vec<u8> = match key.alg {
        DpopAlg::Es256 => {
            use p256::ecdsa::{Signature, SigningKey, signature::Signer};
            let sk = SigningKey::from_bytes(key.d.as_slice().into())
                .map_err(|e| OAuthError::Other(format!("invalid P-256 key: {e}")))?;
            let sig: Signature = sk.sign(signing_input.as_bytes());
            sig.to_bytes().to_vec()
        }
        DpopAlg::Es256k => {
            use k256::ecdsa::{Signature, SigningKey, signature::Signer};
            let sk = SigningKey::from_bytes(key.d.as_slice().into())
                .map_err(|e| OAuthError::Other(format!("invalid secp256k1 key: {e}")))?;
            let sig: Signature = sk.sign(signing_input.as_bytes());
            sig.to_bytes().to_vec()
        }
    };
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);
    Ok(format!("{signing_input}.{sig_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate an ES256 test key. Returns `(ClientKey, verifying_jwk)`.
    fn gen_es256_key(kid: &str) -> ClientKey {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;
        let sk = SigningKey::random(&mut OsRng);
        ClientKey {
            alg: DpopAlg::Es256,
            kid: kid.to_string(),
            d: sk.to_bytes().to_vec(),
        }
    }

    #[test]
    fn build_client_assertion_emits_three_segment_jws() {
        let key = gen_es256_key("key-1");
        let jws = build_client_assertion(&key, "https://app.example/cm", "https://as/token").unwrap();
        assert_eq!(jws.matches('.').count(), 2);

        let mut it = jws.split('.');
        let header_b64 = it.next().unwrap();
        let payload_b64 = it.next().unwrap();

        let header: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(header_b64).unwrap()
        ).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], "key-1");

        let payload: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(payload_b64).unwrap()
        ).unwrap();
        assert_eq!(payload["iss"], "https://app.example/cm");
        assert_eq!(payload["sub"], "https://app.example/cm");
        assert_eq!(payload["aud"], "https://as/token");
        assert!(payload["jti"].is_string());
        let iat = payload["iat"].as_i64().unwrap();
        let exp = payload["exp"].as_i64().unwrap();
        assert_eq!(exp - iat, 60);
    }

    #[test]
    fn client_assertion_signature_verifies_against_corresponding_public_key() {
        use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Verifier};

        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let vk: VerifyingKey = *sk.verifying_key();
        let key = ClientKey {
            alg: DpopAlg::Es256,
            kid: "k".into(),
            d: sk.to_bytes().to_vec(),
        };
        let jws = build_client_assertion(&key, "https://c", "https://t").unwrap();

        let mut it = jws.split('.');
        let h = it.next().unwrap();
        let p = it.next().unwrap();
        let s = it.next().unwrap();
        let signing_input = format!("{h}.{p}");
        let sig_bytes = URL_SAFE_NO_PAD.decode(s).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        vk.verify(signing_input.as_bytes(), &sig).unwrap();
    }

    #[test]
    fn keyset_selects_first_compatible_alg() {
        let k1 = gen_es256_key("a");
        let ks = ClientKeyset::new().with_key(k1.clone());

        // Only ES256K advertised → no match.
        assert!(ks.select_for(&["ES256K".to_string()]).is_none());

        // ES256 advertised → picks our key.
        let picked = ks.select_for(&["ES256".to_string()]).unwrap();
        assert_eq!(picked.kid, "a");

        // Both advertised → still ES256 (first match).
        let picked = ks.select_for(&["RS256".to_string(), "ES256".to_string()]).unwrap();
        assert_eq!(picked.kid, "a");
    }
}
