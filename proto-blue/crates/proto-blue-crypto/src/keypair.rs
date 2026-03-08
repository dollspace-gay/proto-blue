//! Trait definitions for cryptographic keypairs.

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
