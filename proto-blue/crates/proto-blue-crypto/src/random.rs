//! Random-data helpers.
//!
//! Mirrors TS `@atproto/crypto/random.ts`. Uses `rand::OsRng` under
//! the hood, so entropy comes from the OS (or `crypto.getRandomValues`
//! on wasm via the `getrandom/js` shim configured in
//! `proto-blue-crypto/Cargo.toml`).

use rand::{Rng, RngCore, SeedableRng};

/// Generate `n` cryptographically secure random bytes.
#[must_use]
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

/// Generate a random string of `n` bytes in the requested encoding.
/// Matches TS `randomStr(len, encoding)`:
///
/// - `"hex"` — lowercase hex, length = `2 * n`
/// - `"base32"` — RFC 4648 lowercase base32 (no padding)
/// - `"base58"` — bitcoin-style base58btc
/// - `"base64"` — standard base64 (no padding)
/// - `"base64url"` — URL-safe base64 (no padding)
#[must_use]
pub fn random_str(n: usize, encoding: StrEncoding) -> String {
    let bytes = random_bytes(n);
    match encoding {
        StrEncoding::Hex => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        StrEncoding::Base32 => base32_encode(&bytes),
        StrEncoding::Base58btc => bs58::encode(&bytes).into_string(),
        StrEncoding::Base64 => {
            use base64::Engine as _;
            let engine = base64::engine::GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                base64::engine::GeneralPurposeConfig::new().with_encode_padding(false),
            );
            engine.encode(&bytes)
        }
        StrEncoding::Base64Url => {
            use base64::Engine as _;
            let engine = base64::engine::GeneralPurpose::new(
                &base64::alphabet::URL_SAFE,
                base64::engine::GeneralPurposeConfig::new().with_encode_padding(false),
            );
            engine.encode(&bytes)
        }
    }
}

/// Encodings for [`random_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrEncoding {
    Hex,
    Base32,
    Base58btc,
    Base64,
    Base64Url,
}

/// Produce a deterministic pseudo-random integer in `[low, high)` from
/// a byte seed. Mirrors TS `randomIntFromSeed(seed, high, low)`.
///
/// Uses `ChaCha20` seeded from the SHA-256 of `seed`. Not for
/// cryptographic use (that's what [`random_bytes`] is for) — this is
/// for **reproducible** load-balancing, sharding, and shuffle seeds.
#[must_use]
pub fn random_int_from_seed(seed: &[u8], low: i64, high: i64) -> i64 {
    assert!(high > low, "random_int_from_seed: high must exceed low");
    let hash = super::sha::sha256(seed);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(hash);
    rng.gen_range(low..high)
}

/// Minimal RFC 4648 base32 encoder (lowercase, no padding).
///
/// `base32` crate adds a 300 KB dependency for one operation; we do
/// it inline.
fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut bits: u16 = 0;
    let mut bit_count: u8 = 0;
    for &b in bytes {
        bits = (bits << 8) | u16::from(b);
        bit_count += 8;
        while bit_count >= 5 {
            let idx = (bits >> (bit_count - 5)) & 0x1f;
            out.push(ALPHABET[idx as usize] as char);
            bit_count -= 5;
            bits &= (1 << bit_count) - 1;
        }
    }
    if bit_count > 0 {
        let idx = (bits << (5 - bit_count)) & 0x1f;
        out.push(ALPHABET[idx as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_length() {
        assert_eq!(random_bytes(16).len(), 16);
        assert_eq!(random_bytes(32).len(), 32);
        assert_eq!(random_bytes(0).len(), 0);
    }

    #[test]
    fn random_bytes_distinct() {
        // Two draws of 32 bytes are overwhelmingly unlikely to collide.
        let a = random_bytes(32);
        let b = random_bytes(32);
        assert_ne!(a, b);
    }

    #[test]
    fn random_str_hex_length() {
        let s = random_str(16, StrEncoding::Hex);
        assert_eq!(s.len(), 32);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn random_str_base32_no_padding() {
        let s = random_str(10, StrEncoding::Base32);
        assert!(!s.contains('='));
    }

    #[test]
    fn random_str_base64_no_padding() {
        let s = random_str(20, StrEncoding::Base64);
        assert!(!s.contains('='));
    }

    #[test]
    fn random_int_from_seed_is_deterministic() {
        let a = random_int_from_seed(b"hello", 0, 1_000_000);
        let b = random_int_from_seed(b"hello", 0, 1_000_000);
        assert_eq!(a, b, "same seed must yield same result");
        assert!((0..1_000_000).contains(&a));
    }

    #[test]
    fn random_int_from_seed_varies_per_seed() {
        let a = random_int_from_seed(b"seed-a", 0, 1_000_000);
        let b = random_int_from_seed(b"seed-b", 0, 1_000_000);
        assert_ne!(a, b);
    }

    #[test]
    #[should_panic(expected = "high must exceed low")]
    fn random_int_from_seed_panics_on_empty_range() {
        let _ = random_int_from_seed(b"x", 0, 0);
    }

    #[test]
    fn base32_encode_known_vector() {
        // RFC 4648 examples: "foobar" -> "mzxw6ytboi" (lowercase)
        assert_eq!(base32_encode(b"foobar"), "mzxw6ytboi");
        assert_eq!(base32_encode(b""), "");
    }
}
