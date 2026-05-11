//! SHA-256 hashing.

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Compute the SHA-256 hash of the input bytes.
#[must_use]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute the SHA-256 hash of the input bytes as a lowercase hex
/// string. Mirrors TS `sha256Hex`.
#[must_use]
pub fn sha256_hex(input: &[u8]) -> String {
    let bytes = sha256(input);
    let mut s = String::with_capacity(64);
    for b in bytes {
        write!(s, "{b:02x}").expect("write to String is infallible");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha256_known_vector() {
        let hash = sha256(b"");
        assert_eq!(
            to_hex(&hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hello() {
        let hash = sha256(b"hello");
        assert_eq!(
            to_hex(&hash),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
