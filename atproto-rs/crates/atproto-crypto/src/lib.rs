//! AT Protocol cryptographic operations.
//!
//! Provides P-256 and secp256k1 key generation, signing, and verification,
//! as well as `did:key` encoding/decoding and SHA-256 hashing.
//!
//! # Examples
//!
//! ```
//! use atproto_crypto::{P256Keypair, Keypair, Signer, Verifier, sha256, format_did_key, parse_did_key};
//!
//! // Generate a P-256 keypair and sign data
//! let kp = P256Keypair::generate();
//! let msg = b"Hello, AT Protocol!";
//! let sig = kp.sign(msg).unwrap();
//!
//! // Verify using a verifier from the compressed public key
//! let compressed = kp.public_key_compressed();
//! let verifier = P256Keypair::verifier_from_compressed(&compressed).unwrap();
//! assert!(verifier.verify(msg, &sig).unwrap());
//!
//! // Encode as did:key
//! let did_key = format_did_key("ES256", &compressed);
//! assert!(did_key.starts_with("did:key:z"));
//!
//! // Parse did:key back
//! let parsed = parse_did_key(&did_key).unwrap();
//! assert_eq!(parsed.jwt_alg, "ES256");
//!
//! // SHA-256 hashing
//! let hash = sha256(b"Hello, world!");
//! assert_eq!(hash.len(), 32);
//! ```

mod did_key;
mod error;
mod k256_impl;
mod keypair;
mod p256_impl;
mod sha;

pub use did_key::{
    K256_DID_PREFIX, P256_DID_PREFIX, ParsedMultikey, format_did_key, format_multikey,
    parse_did_key, parse_multikey, verify_signature,
};
pub use error::CryptoError;
pub use k256_impl::{K256Keypair, compress_pubkey as k256_compress_pubkey};
pub use keypair::{ExportableKeypair, Keypair, Signer, Verifier};
pub use p256_impl::{P256Keypair, compress_pubkey as p256_compress_pubkey};
pub use sha::sha256;
