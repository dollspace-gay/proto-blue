//! Trait definitions for cryptographic keypairs.
//!
//! `Keypair` (signing + public identity) and `ExportableKeypair` (also
//! private-key export) are intentionally split, so a caller can receive
//! a handle that can sign but cannot exfiltrate the private material.
//! `SealedKeypair` wraps any `ExportableKeypair` and *drops* the export
//! capability at the type level.

use crate::CryptoError;

/// A type that can produce digital signatures.
pub trait Signer: Send + Sync {
    /// The JWT algorithm identifier (e.g., `"ES256"` or `"ES256K"`).
    fn jwt_alg(&self) -> &str;

    /// Sign a message, returning the raw compact signature bytes (64 bytes: R || S).
    ///
    /// The message is SHA-256 hashed internally before signing.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// A type that can verify digital signatures.
pub trait Verifier: Send + Sync {
    /// Verify a signature against a message.
    ///
    /// The message is SHA-256 hashed internally before verification.
    /// By default, requires low-S normalized compact signatures.
    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError>;

    /// Verify a signature, optionally allowing malleable (high-S or DER) signatures.
    fn verify_malleable(&self, msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError>;
}

/// A full keypair that can sign and provide its DID.
pub trait Keypair: Signer {
    /// Return the `did:key:z...` string for this keypair's public key.
    fn did(&self) -> String;

    /// Return the compressed public key bytes (33 bytes).
    fn public_key_compressed(&self) -> Vec<u8>;
}

/// A keypair that can export its private key.
pub trait ExportableKeypair: Keypair {
    /// Export the raw private key bytes.
    fn export_private_key(&self) -> Vec<u8>;
}

/// A keypair wrapper that can sign and identify itself but *cannot*
/// export its private key at the type level. Pass the inner keypair in
/// at construction time, then hand out the sealed wrapper to any code
/// that should not be able to exfiltrate the secret.
///
/// The sealed wrapper owns the inner keypair, so the original value is
/// consumed. If the caller holds onto the original they can still
/// export it — the sealing only applies to what's handed out.
///
/// Signing and identity still work:
///
/// ```
/// use proto_blue_crypto::{Keypair, P256Keypair, SealedKeypair, Signer};
///
/// let kp = P256Keypair::generate();
/// let sealed = SealedKeypair::seal(kp);
///
/// let sig = sealed.sign(b"hello").unwrap();
/// assert_eq!(sig.len(), 64);
/// assert!(sealed.did().starts_with("did:key:z"));
/// ```
///
/// But `export_private_key` does not compile against a sealed wrapper:
///
/// ```compile_fail
/// use proto_blue_crypto::{ExportableKeypair, P256Keypair, SealedKeypair};
/// let kp = P256Keypair::generate();
/// let sealed = SealedKeypair::seal(kp);
/// // Must not compile: SealedKeypair does not implement ExportableKeypair.
/// let _ = sealed.export_private_key();
/// ```
pub struct SealedKeypair<K: Keypair> {
    inner: K,
}

impl<K: Keypair> SealedKeypair<K> {
    /// Wrap a keypair to drop its export capability at the type level.
    /// Accepts any `Keypair` — including non-exportable ones — so you
    /// can re-seal something that's already sealed (no-op semantically).
    pub const fn seal(inner: K) -> Self {
        Self { inner }
    }
}

impl<K: Keypair> Signer for SealedKeypair<K> {
    fn jwt_alg(&self) -> &str {
        self.inner.jwt_alg()
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.sign(msg)
    }
}

impl<K: Keypair> Keypair for SealedKeypair<K> {
    fn did(&self) -> String {
        self.inner.did()
    }
    fn public_key_compressed(&self) -> Vec<u8> {
        self.inner.public_key_compressed()
    }
}

// Deliberately no `impl ExportableKeypair for SealedKeypair<K>` — that's
// the whole point. The test suite includes a compile-time check that
// verifies this.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::P256Keypair;

    #[test]
    fn sealed_keypair_can_sign_and_identify() {
        let kp = P256Keypair::generate();
        let did_before = kp.did();
        let compressed_before = kp.public_key_compressed();

        let sealed = SealedKeypair::seal(kp);
        assert_eq!(sealed.jwt_alg(), "ES256");
        assert_eq!(sealed.did(), did_before);
        assert_eq!(sealed.public_key_compressed(), compressed_before);

        // Signing still works.
        let sig = sealed.sign(b"hello sealed world").unwrap();
        assert_eq!(sig.len(), 64);
    }

    /// Sealing an already-sealed keypair is a no-op — you can re-wrap
    /// indefinitely without losing signing capability or changing the DID.
    #[test]
    fn reseal_is_a_noop() {
        let kp = P256Keypair::generate();
        let did = kp.did();
        let sealed = SealedKeypair::seal(kp);
        let resealed = SealedKeypair::seal(sealed);
        assert_eq!(resealed.did(), did);
        assert_eq!(resealed.jwt_alg(), "ES256");
    }
}
