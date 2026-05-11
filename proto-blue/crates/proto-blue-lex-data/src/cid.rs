//! Content Identifier (CID) implementation for AT Protocol.
//!
//! CIDs are self-describing content-addressed identifiers used in IPLD.
//! AT Protocol uses `CIDv1` with DAG-CBOR (0x71) or raw (0x55) codecs
//! and SHA-256 (0x12) hashing exclusively.

use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

/// Multicodec code for DAG-CBOR.
pub const CBOR_CODEC: u64 = 0x71;

/// Multicodec code for raw binary.
pub const RAW_CODEC: u64 = 0x55;

/// Multihash code for SHA-256.
pub const SHA2_256: u64 = 0x12;

/// Multihash code for SHA-512.
pub const SHA2_512: u64 = 0x13;

/// SHA-256 digest length in bytes.
const SHA256_DIGEST_LEN: usize = 32;

/// A content identifier (`CIDv1`) as used in AT Protocol.
///
/// The digest is stored inline as `[u8; 32]` rather than `Vec<u8>` —
/// every AT Protocol CID is SHA-256 (DASL-compliant), so the hash is
/// always exactly 32 bytes. Inline storage eliminates the per-CID heap
/// allocation that the `Vec<u8>` form imposed and tightens the type's
/// guarantees so a structurally-malformed CID can't exist as a value
/// (parsing rejects non-32-byte digests via [`Cid::from_bytes`]).
// `Copy` is intentionally NOT derived even though every field is
// `Copy` — the existing workspace constructs CIDs via `cid.clone()`
// in many places, and adding `Copy` would trigger a `clippy::clone_on_copy`
// sweep across hundreds of unrelated call sites. The audit's concern
// (heap allocation per CID) is addressed entirely by the inline-array
// digest; making the type `Copy` is a separable cleanup that would
// touch every consumer.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid {
    /// CID version (always 1 for AT Protocol).
    pub version: u64,
    /// Multicodec code for the data codec (0x71 = DAG-CBOR, 0x55 = raw).
    pub codec: u64,
    /// Multihash algorithm code (0x12 = SHA-256).
    pub hash_code: u64,
    /// The raw hash digest bytes (always 32 bytes — SHA-256).
    pub digest: [u8; 32],
}

/// Errors that can occur when working with CIDs.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CidError {
    #[error("Invalid CID: {0}")]
    Invalid(String),
    #[error("Unsupported CID version: {0}")]
    UnsupportedVersion(u64),
    #[error("Unsupported codec: 0x{0:x}")]
    UnsupportedCodec(u64),
    #[error("Unsupported hash algorithm: 0x{0:x}")]
    UnsupportedHash(u64),
    #[error("Invalid digest length: expected {expected}, got {actual}")]
    InvalidDigestLength { expected: usize, actual: usize },
    #[error("Multibase decode error: {0}")]
    MultibaseDecode(String),
    #[error("Varint decode error: {0}")]
    VarintDecode(String),
}

impl Cid {
    /// Create a new `CIDv1` directly. Most callers should prefer
    /// [`Cid::for_cbor`] / [`Cid::for_raw`] instead, which compute the
    /// SHA-256 digest from data.
    #[must_use]
    pub const fn new(codec: u64, hash_code: u64, digest: [u8; 32]) -> Self {
        Self {
            version: 1,
            codec,
            hash_code,
            digest,
        }
    }

    /// Create a `CIDv1` for DAG-CBOR data by hashing with SHA-256.
    #[must_use]
    pub fn for_cbor(cbor_bytes: &[u8]) -> Self {
        Self::new(CBOR_CODEC, SHA2_256, Sha256::digest(cbor_bytes).into())
    }

    /// Create a `CIDv1` for raw data by hashing with SHA-256.
    #[must_use]
    pub fn for_raw(raw_bytes: &[u8]) -> Self {
        Self::new(RAW_CODEC, SHA2_256, Sha256::digest(raw_bytes).into())
    }

    /// Create a CID from a raw SHA-256 digest with raw codec.
    #[must_use]
    pub const fn for_raw_hash(digest: [u8; 32]) -> Self {
        Self::new(RAW_CODEC, SHA2_256, digest)
    }

    /// Check if this CID is DASL-compliant (AT Protocol requirements).
    ///
    /// DASL CIDs must be `CIDv1`, use raw or DAG-CBOR codec, SHA-256 hash.
    /// The 32-byte digest length is now an invariant of the type so it
    /// no longer needs to be checked at runtime.
    #[must_use]
    pub const fn is_dasl_compliant(&self) -> bool {
        self.version == 1
            && (self.codec == RAW_CODEC || self.codec == CBOR_CODEC)
            && self.hash_code == SHA2_256
    }

    /// Verify that this CID matches the given bytes.
    pub fn verify(&self, data: &[u8]) -> Result<bool, CidError> {
        match self.hash_code {
            SHA2_256 => {
                let computed = Sha256::digest(data);
                Ok(computed[..] == self.digest[..])
            }
            other => Err(CidError::UnsupportedHash(other)),
        }
    }

    /// Encode this CID to its binary representation.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Version
        encode_varint(self.version, &mut buf);
        // Codec
        encode_varint(self.codec, &mut buf);
        // Multihash: hash code + digest length + digest
        encode_varint(self.hash_code, &mut buf);
        encode_varint(self.digest.len() as u64, &mut buf);
        buf.extend_from_slice(&self.digest);
        buf
    }

    /// Parse a CID from its binary representation.
    ///
    /// Rejects digests that aren't exactly 32 bytes (the SHA-256 size
    /// AT Protocol uses universally) — the type's `digest: [u8; 32]`
    /// invariant means a structurally-malformed CID can't exist as a
    /// value, so wire input is checked at the parse boundary.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CidError> {
        let mut pos = 0;

        let version = read_varint(bytes, &mut pos)?;
        if version != 1 {
            return Err(CidError::UnsupportedVersion(version));
        }

        let codec = read_varint(bytes, &mut pos)?;
        let hash_code = read_varint(bytes, &mut pos)?;
        // digest_len is validated against SHA256_DIGEST_LEN (= 32) immediately below;
        // any wire u64 that doesn't fit usize would also fail that check (32 is well
        // inside the usize range on every supported target). Truncation is harmless.
        #[allow(clippy::cast_possible_truncation)]
        let digest_len = read_varint(bytes, &mut pos)? as usize;

        // The digest is always 32 bytes for AT Protocol (SHA-256). A
        // length mismatch here is either malformed input from the wire
        // or a non-DASL CID that doesn't fit our type. Reject at the
        // parse boundary rather than carry it as a value.
        if digest_len != SHA256_DIGEST_LEN {
            return Err(CidError::InvalidDigestLength {
                expected: SHA256_DIGEST_LEN,
                actual: digest_len,
            });
        }

        // `pos + digest_len` can overflow `usize` on adversarial
        // input (huge varint). `checked_add` turns that from a
        // runtime panic into a structured error — important because
        // CID bytes come from untrusted sources (firehose, CAR
        // blocks from peers). With the strict length check above this
        // is now defensive but cheap; left in place.
        let digest_end = pos
            .checked_add(SHA256_DIGEST_LEN)
            .ok_or_else(|| CidError::Invalid("CID position overflows usize".to_string()))?;
        if digest_end > bytes.len() {
            return Err(CidError::Invalid(format!(
                "CID bytes too short: need {} more bytes, have {}",
                SHA256_DIGEST_LEN,
                bytes.len().saturating_sub(pos)
            )));
        }

        let mut digest = [0u8; SHA256_DIGEST_LEN];
        digest.copy_from_slice(&bytes[pos..digest_end]);

        Ok(Self {
            version,
            codec,
            hash_code,
            digest,
        })
    }

    /// Parse a CID from a multibase-encoded string.
    ///
    /// `CIDv1` strings use base32lower by default (prefix 'b').
    pub fn from_str_multibase(s: &str) -> Result<Self, CidError> {
        if s.is_empty() {
            return Err(CidError::Invalid("Empty CID string".to_string()));
        }

        let (_, bytes) =
            multibase::decode(s).map_err(|e| CidError::MultibaseDecode(e.to_string()))?;

        Self::from_bytes(&bytes)
    }

    /// Encode this CID as a multibase string (base32lower, prefix 'b').
    #[must_use]
    pub fn to_string_base32(&self) -> String {
        let bytes = self.to_bytes();
        multibase::encode(multibase::Base::Base32Lower, &bytes)
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_base32())
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cid({})", self.to_string_base32())
    }
}

impl FromStr for Cid {
    type Err = CidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_multibase(s)
    }
}

impl serde::Serialize for Cid {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // When serializing to JSON, CIDs are represented as {"$link": "bafy..."}
        // But the raw serialization is just the string form.
        // The $link wrapping is handled by atproto-lex-json.
        serializer.serialize_str(&self.to_string_base32())
    }
}

impl<'de> serde::Deserialize<'de> for Cid {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_str_multibase(&s).map_err(serde::de::Error::custom)
    }
}

/// Encode a u64 as an unsigned varint into `buf`.
fn encode_varint(mut value: u64, buf: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Read an unsigned varint from `bytes` starting at `pos`, advancing `pos`.
fn read_varint(bytes: &[u8], pos: &mut usize) -> Result<u64, CidError> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;

    loop {
        if *pos >= bytes.len() {
            return Err(CidError::VarintDecode(
                "Unexpected end of varint".to_string(),
            ));
        }

        let byte = bytes[*pos];
        *pos += 1;

        value |= u64::from(byte & 0x7F) << shift;

        if byte & 0x80 == 0 {
            return Ok(value);
        }

        shift += 7;
        if shift >= 64 {
            return Err(CidError::VarintDecode("Varint too large".to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_for_cbor_creates_valid_cid() {
        let data = b"hello world";
        let cid = Cid::for_cbor(data);
        assert_eq!(cid.version, 1);
        assert_eq!(cid.codec, CBOR_CODEC);
        assert_eq!(cid.hash_code, SHA2_256);
        assert_eq!(cid.digest.len(), 32);
        assert!(cid.is_dasl_compliant());
    }

    #[test]
    fn cid_for_raw_creates_valid_cid() {
        let data = b"hello world";
        let cid = Cid::for_raw(data);
        assert_eq!(cid.version, 1);
        assert_eq!(cid.codec, RAW_CODEC);
        assert_eq!(cid.hash_code, SHA2_256);
        assert!(cid.is_dasl_compliant());
    }

    #[test]
    fn bytes_roundtrip() {
        let cid = Cid::for_cbor(b"test data");
        let bytes = cid.to_bytes();
        let parsed = Cid::from_bytes(&bytes).unwrap();
        assert_eq!(cid, parsed);
    }

    #[test]
    fn string_roundtrip() {
        let cid = Cid::for_cbor(b"test data");
        let s = cid.to_string();
        let parsed: Cid = s.parse().unwrap();
        assert_eq!(cid, parsed);
    }

    #[test]
    fn verify_matching_data() {
        let data = b"verify me";
        let cid = Cid::for_cbor(data);
        assert!(cid.verify(data).unwrap());
        assert!(!cid.verify(b"wrong data").unwrap());
    }

    #[test]
    fn varint_roundtrip() {
        for val in [0u64, 1, 127, 128, 255, 300, 65535, 1_000_000] {
            let mut buf = Vec::new();
            encode_varint(val, &mut buf);
            let mut pos = 0;
            let decoded = read_varint(&buf, &mut pos).unwrap();
            assert_eq!(val, decoded, "varint roundtrip failed for {val}");
        }
    }

    #[test]
    fn dasl_compliance() {
        let valid = Cid::for_cbor(b"data");
        assert!(valid.is_dasl_compliant());

        let invalid = Cid {
            version: 0,
            codec: CBOR_CODEC,
            hash_code: SHA2_256,
            digest: [0u8; 32],
        };
        assert!(!invalid.is_dasl_compliant());
    }

    #[test]
    fn display_starts_with_b() {
        let cid = Cid::for_cbor(b"test");
        let s = cid.to_string();
        assert!(
            s.starts_with('b'),
            "CIDv1 base32lower should start with 'b': {s}"
        );
    }

    #[test]
    fn serde_roundtrip() {
        let cid = Cid::for_cbor(b"serde test");
        let json = serde_json::to_string(&cid).unwrap();
        let parsed: Cid = serde_json::from_str(&json).unwrap();
        assert_eq!(cid, parsed);
    }

    /// Regression: a varint that decodes to a length close to
    /// `usize::MAX` would overflow `pos + digest_len` and panic on
    /// the subsequent `>` compare (debug mode) or wrap and read out
    /// of bounds (release). Found by the `lex_cbor_decode`,
    /// `lex_cbor_canonical`, and `car_parse` fuzzers independently.
    /// Fixed in [`Cid::from_bytes`] with `checked_add`.
    #[test]
    fn from_bytes_rejects_overflowing_digest_length() {
        // version=1, codec=0x71, hash=0x12, digest_len=usize::MAX-ish
        // (10-byte varint with the continuation bit set on every
        // byte except the last).
        let mut bytes = vec![0x01, 0x71, 0x12];
        bytes.extend_from_slice(&[0xff; 9]);
        bytes.push(0x01);
        let err = Cid::from_bytes(&bytes).unwrap_err();
        // Any CidError variant is acceptable — the critical property
        // is that we didn't panic.
        assert!(matches!(
            err,
            CidError::Invalid(_) | CidError::VarintDecode(_) | CidError::InvalidDigestLength { .. }
        ));
    }
}
