//! NIST P-256 (secp256r1) keypair implementation.

use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey, signature::Signer as _, signature::Verifier as _,
};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use rand::rngs::OsRng;

use crate::did_key::format_did_key;
use crate::error::CryptoError;
use crate::keypair;
use crate::sha;

/// A P-256 (NIST secp256r1) ECDSA keypair.
///
/// JWT algorithm: `ES256`
pub struct P256Keypair {
    signing_key: SigningKey,
}

impl P256Keypair {
    /// Generate a new random P-256 keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        P256Keypair { signing_key }
    }

    /// Create a keypair from raw private key bytes (32 bytes).
    pub fn from_private_key(bytes: &[u8]) -> Result<Self, CryptoError> {
        let secret_key =
            SecretKey::from_slice(bytes).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        Ok(P256Keypair {
            signing_key: SigningKey::from(secret_key),
        })
    }

    /// Return the verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
    }

    /// Return a verifier for a compressed public key (33 bytes).
    pub fn verifier_from_compressed(compressed: &[u8]) -> Result<P256Verifier, CryptoError> {
        let point = EncodedPoint::from_bytes(compressed)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let public_key = PublicKey::from_encoded_point(&point);
        if public_key.is_none().into() {
            return Err(CryptoError::InvalidKey(
                "Invalid P-256 compressed public key".to_string(),
            ));
        }
        let verifying_key = VerifyingKey::from(public_key.unwrap());
        Ok(P256Verifier { verifying_key })
    }
}

impl keypair::Signer for P256Keypair {
    fn jwt_alg(&self) -> &str {
        "ES256"
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let msg_hash = sha::sha256(msg);
        let sig: Signature = self.signing_key.sign(&msg_hash);
        let normalized = sig.normalize_s().unwrap_or(sig);
        Ok(normalized.to_bytes().to_vec())
    }
}

impl keypair::Keypair for P256Keypair {
    fn did(&self) -> String {
        let compressed = self.public_key_compressed();
        format_did_key("ES256", &compressed)
    }

    fn public_key_compressed(&self) -> Vec<u8> {
        let vk = self.verifying_key();
        let point = vk.to_encoded_point(true); // true = compressed
        point.as_bytes().to_vec()
    }
}

impl keypair::ExportableKeypair for P256Keypair {
    fn export_private_key(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }
}

/// A P-256 public key verifier (no private key).
pub struct P256Verifier {
    verifying_key: VerifyingKey,
}

impl keypair::Verifier for P256Verifier {
    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
        let msg_hash = sha::sha256(msg);
        let signature = Signature::from_slice(sig)
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;

        // Reject high-S signatures
        if signature.normalize_s().is_some() {
            return Ok(false);
        }

        match self.verifying_key.verify(&msg_hash, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_malleable(&self, msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
        let msg_hash = sha::sha256(msg);

        // Try compact format first
        if let Ok(signature) = Signature::from_slice(sig) {
            let normalized = signature.normalize_s().unwrap_or(signature);
            if self.verifying_key.verify(&msg_hash, &normalized).is_ok() {
                return Ok(true);
            }
        }

        // Try DER format
        if let Ok(signature) = Signature::from_der(sig) {
            let normalized = signature.normalize_s().unwrap_or(signature);
            if self.verifying_key.verify(&msg_hash, &normalized).is_ok() {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

/// Compress a P-256 public key.
pub fn compress_pubkey(uncompressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let point = EncodedPoint::from_bytes(uncompressed)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    let pk = PublicKey::from_encoded_point(&point);
    if pk.is_none().into() {
        return Err(CryptoError::InvalidKey("Invalid P-256 point".to_string()));
    }
    Ok(pk.unwrap().to_encoded_point(true).as_bytes().to_vec())
}

/// Decompress a P-256 public key.
pub fn decompress_pubkey(compressed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if compressed.len() != 33 {
        return Err(CryptoError::InvalidKey(format!(
            "Expected 33 byte compressed pubkey, got {}",
            compressed.len()
        )));
    }
    let point =
        EncodedPoint::from_bytes(compressed).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    let pk = PublicKey::from_encoded_point(&point);
    if pk.is_none().into() {
        return Err(CryptoError::InvalidKey("Invalid P-256 point".to_string()));
    }
    Ok(pk.unwrap().to_encoded_point(false).as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::{ExportableKeypair, Keypair, Signer, Verifier};

    #[test]
    fn generate_and_sign_verify() {
        let kp = P256Keypair::generate();
        let msg = b"hello atproto";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), 64, "P-256 compact signature should be 64 bytes");

        let verifier = P256Keypair::verifier_from_compressed(&kp.public_key_compressed()).unwrap();
        assert!(verifier.verify(msg, &sig).unwrap());
        assert!(!verifier.verify(b"wrong message", &sig).unwrap());
    }

    #[test]
    fn did_key_format() {
        let kp = P256Keypair::generate();
        let did = kp.did();
        assert!(
            did.starts_with("did:key:z"),
            "DID should start with did:key:z"
        );
    }

    #[test]
    fn export_reimport() {
        let kp = P256Keypair::generate();
        let private_bytes = kp.export_private_key();
        let kp2 = P256Keypair::from_private_key(&private_bytes).unwrap();
        assert_eq!(kp.public_key_compressed(), kp2.public_key_compressed());
    }

    #[test]
    fn compress_decompress_roundtrip() {
        let kp = P256Keypair::generate();
        let compressed = kp.public_key_compressed();
        assert_eq!(compressed.len(), 33);

        let uncompressed = decompress_pubkey(&compressed).unwrap();
        assert_eq!(uncompressed.len(), 65);

        let recompressed = compress_pubkey(&uncompressed).unwrap();
        assert_eq!(compressed, recompressed);
    }
}
