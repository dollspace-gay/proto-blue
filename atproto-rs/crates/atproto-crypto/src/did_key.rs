//! DID:key encoding and decoding.
//!
//! Format: `did:key:z<base58btc(multicodec_prefix || compressed_pubkey)>`
//!
//! Multicodec prefixes:
//! - P-256: `[0x80, 0x24]`
//! - secp256k1: `[0xe7, 0x01]`

use crate::error::CryptoError;

/// Multicodec prefix for P-256 (p256-pub).
pub const P256_DID_PREFIX: [u8; 2] = [0x80, 0x24];

/// Multicodec prefix for secp256k1 (secp256k1-pub).
pub const K256_DID_PREFIX: [u8; 2] = [0xe7, 0x01];

/// Base58btc multibase prefix character.
const BASE58_MULTIBASE_PREFIX: char = 'z';

/// DID:key URI prefix.
const DID_KEY_PREFIX: &str = "did:key:";

/// Parsed multikey result.
#[derive(Debug, Clone)]
pub struct ParsedMultikey {
    /// The JWT algorithm identifier (`"ES256"` or `"ES256K"`).
    pub jwt_alg: String,
    /// The uncompressed public key bytes (65 bytes).
    pub key_bytes: Vec<u8>,
}

/// Format a public key as a `did:key:z...` string.
///
/// The `jwt_alg` must be `"ES256"` (P-256) or `"ES256K"` (secp256k1).
/// The `compressed_pubkey` must be 33 bytes (compressed SEC1 point).
pub fn format_did_key(jwt_alg: &str, compressed_pubkey: &[u8]) -> String {
    let multikey = format_multikey(jwt_alg, compressed_pubkey);
    format!("{DID_KEY_PREFIX}{multikey}")
}

/// Format a public key as a multibase-encoded multikey string (`z...`).
pub fn format_multikey(jwt_alg: &str, compressed_pubkey: &[u8]) -> String {
    let prefix = prefix_for_alg(jwt_alg).expect("Unsupported JWT algorithm");

    let mut prefixed_bytes = Vec::with_capacity(prefix.len() + compressed_pubkey.len());
    prefixed_bytes.extend_from_slice(prefix);
    prefixed_bytes.extend_from_slice(compressed_pubkey);

    let encoded = bs58::encode(&prefixed_bytes).into_string();
    format!("{BASE58_MULTIBASE_PREFIX}{encoded}")
}

/// Parse a `did:key:z...` string, returning the algorithm and uncompressed public key.
pub fn parse_did_key(did: &str) -> Result<ParsedMultikey, CryptoError> {
    let multikey = did
        .strip_prefix(DID_KEY_PREFIX)
        .ok_or_else(|| CryptoError::InvalidDidKey(format!("Missing prefix: {DID_KEY_PREFIX}")))?;

    parse_multikey(multikey)
}

/// Parse a multibase-encoded multikey string (`z...`).
pub fn parse_multikey(multikey: &str) -> Result<ParsedMultikey, CryptoError> {
    if !multikey.starts_with(BASE58_MULTIBASE_PREFIX) {
        return Err(CryptoError::InvalidMultikey(format!(
            "Expected base58btc prefix '{BASE58_MULTIBASE_PREFIX}'"
        )));
    }

    let encoded = &multikey[1..]; // Strip 'z' prefix
    let prefixed_bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| CryptoError::DecodeError(format!("Base58 decode failed: {e}")))?;

    if prefixed_bytes.len() < 2 {
        return Err(CryptoError::InvalidMultikey("Too short".to_string()));
    }

    // Check P-256 prefix
    if starts_with(&prefixed_bytes, &P256_DID_PREFIX) {
        let compressed = &prefixed_bytes[P256_DID_PREFIX.len()..];
        let uncompressed = crate::p256_impl::decompress_pubkey(compressed)?;
        return Ok(ParsedMultikey {
            jwt_alg: "ES256".to_string(),
            key_bytes: uncompressed,
        });
    }

    // Check secp256k1 prefix
    if starts_with(&prefixed_bytes, &K256_DID_PREFIX) {
        let compressed = &prefixed_bytes[K256_DID_PREFIX.len()..];
        let uncompressed = crate::k256_impl::decompress_pubkey(compressed)?;
        return Ok(ParsedMultikey {
            jwt_alg: "ES256K".to_string(),
            key_bytes: uncompressed,
        });
    }

    Err(CryptoError::InvalidMultikey(format!(
        "Unknown multicodec prefix: [{:#04x}, {:#04x}]",
        prefixed_bytes[0], prefixed_bytes[1]
    )))
}

/// Verify a signature using a `did:key` string.
pub fn verify_signature(
    did_key: &str,
    msg: &[u8],
    sig: &[u8],
    allow_malleable: bool,
) -> Result<bool, CryptoError> {
    let parsed = parse_did_key(did_key)?;

    match parsed.jwt_alg.as_str() {
        "ES256" => {
            let compressed = crate::p256_impl::compress_pubkey(&parsed.key_bytes)?;
            let verifier = crate::P256Keypair::verifier_from_compressed(&compressed)?;
            if allow_malleable {
                crate::keypair::Verifier::verify_malleable(&verifier, msg, sig)
            } else {
                crate::keypair::Verifier::verify(&verifier, msg, sig)
            }
        }
        "ES256K" => {
            let compressed = crate::k256_impl::compress_pubkey(&parsed.key_bytes)?;
            let verifier = crate::K256Keypair::verifier_from_compressed(&compressed)?;
            if allow_malleable {
                crate::keypair::Verifier::verify_malleable(&verifier, msg, sig)
            } else {
                crate::keypair::Verifier::verify(&verifier, msg, sig)
            }
        }
        other => Err(CryptoError::UnsupportedAlgorithm(other.to_string())),
    }
}

fn prefix_for_alg(jwt_alg: &str) -> Option<&'static [u8]> {
    match jwt_alg {
        "ES256" => Some(&P256_DID_PREFIX),
        "ES256K" => Some(&K256_DID_PREFIX),
        _ => None,
    }
}

fn starts_with(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes.len() >= prefix.len() && &bytes[..prefix.len()] == prefix
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::Keypair;

    #[test]
    fn p256_did_key_roundtrip() {
        let kp = crate::P256Keypair::generate();
        let did = kp.did();
        assert!(did.starts_with("did:key:z"));

        let parsed = parse_did_key(&did).unwrap();
        assert_eq!(parsed.jwt_alg, "ES256");
        assert_eq!(parsed.key_bytes.len(), 65); // Uncompressed
    }

    #[test]
    fn k256_did_key_roundtrip() {
        let kp = crate::K256Keypair::generate();
        let did = kp.did();
        assert!(did.starts_with("did:key:z"));

        let parsed = parse_did_key(&did).unwrap();
        assert_eq!(parsed.jwt_alg, "ES256K");
        assert_eq!(parsed.key_bytes.len(), 65); // Uncompressed
    }

    #[test]
    fn verify_via_did_key() {
        let kp = crate::P256Keypair::generate();
        let did = kp.did();
        let msg = b"test message";
        let sig = crate::keypair::Signer::sign(&kp, msg).unwrap();

        assert!(verify_signature(&did, msg, &sig, false).unwrap());
        assert!(!verify_signature(&did, b"wrong", &sig, false).unwrap());
    }

    #[test]
    fn invalid_did_key() {
        assert!(parse_did_key("not-a-did").is_err());
        assert!(parse_did_key("did:key:abc").is_err()); // no 'z' prefix
    }

    #[test]
    fn multikey_format() {
        let kp = crate::P256Keypair::generate();
        let compressed = kp.public_key_compressed();
        let multikey = format_multikey("ES256", &compressed);
        assert!(multikey.starts_with('z'));

        let parsed = parse_multikey(&multikey).unwrap();
        assert_eq!(parsed.jwt_alg, "ES256");
    }
}
