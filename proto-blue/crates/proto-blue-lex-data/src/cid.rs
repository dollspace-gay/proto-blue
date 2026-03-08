//! Content Identifier (CID) implementation for AT Protocol.
//!
//! CIDs are self-describing content-addressed identifiers used in IPLD.
//! AT Protocol uses CIDv1 with DAG-CBOR (0x71) or raw (0x55) codecs
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

/// A content identifier (CIDv1) as used in AT Protocol.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid {
    /// CID version (always 1 for AT Protocol).
    pub version: u8,
    /// Multicodec code for the data codec (0x71 = DAG-CBOR, 0x55 = raw).
    pub codec: u64,
    /// Multihash algorithm code (0x12 = SHA-256).
    pub hash_code: u64,
    /// The raw hash digest bytes.
    pub digest: Vec<u8>,
}

/// Errors that can occur when working with CIDs.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CidError {
    #[error("Invalid CID: {0}")]
    Invalid(String),
    #[error("Unsupported CID version: {0}")]
    UnsupportedVersion(u8),
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
    /// Create a new CIDv1.
    pub fn new(codec: u64, hash_code: u64, digest: Vec<u8>) -> Self {
        Cid {
            version: 1,
            codec,
            hash_code,
            digest,
        }
    }

    /// Create a CIDv1 for DAG-CBOR data by hashing with SHA-256.
    pub fn for_cbor(cbor_bytes: &[u8]) -> Self {
        let digest = Sha256::digest(cbor_bytes).to_vec();
        Cid::new(CBOR_CODEC, SHA2_256, digest)
    }

    /// Create a CIDv1 for raw data by hashing with SHA-256.
    pub fn for_raw(raw_bytes: &[u8]) -> Self {
        let digest = Sha256::digest(raw_bytes).to_vec();
        Cid::new(RAW_CODEC, SHA2_256, digest)
    }

    /// Create a CID from a raw SHA-256 digest with raw codec.
    pub fn for_raw_hash(digest: Vec<u8>) -> Result<Self, CidError> {
        if digest.len() != SHA256_DIGEST_LEN {
            return Err(CidError::InvalidDigestLength {
                expected: SHA256_DIGEST_LEN,
                actual: digest.len(),
            });
        }
        Ok(Cid::new(RAW_CODEC, SHA2_256, digest))
    }

    /// Check if this CID is DASL-compliant (AT Protocol requirements).
    ///
    /// DASL CIDs must be CIDv1, use raw or DAG-CBOR codec, SHA-256 hash, 32-byte digest.
    pub fn is_dasl_compliant(&self) -> bool {
        self.version == 1
            && (self.codec == RAW_CODEC || self.codec == CBOR_CODEC)
            && self.hash_code == SHA2_256
            && self.digest.len() == SHA256_DIGEST_LEN
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
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Version
        encode_varint(self.version as u64, &mut buf);
        // Codec
        encode_varint(self.codec, &mut buf);
        // Multihash: hash code + digest length + digest
        encode_varint(self.hash_code, &mut buf);
        encode_varint(self.digest.len() as u64, &mut buf);
        buf.extend_from_slice(&self.digest);
        buf
    }

    /// Parse a CID from its binary representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CidError> {
        let mut pos = 0;

        let version = read_varint(bytes, &mut pos)?;
        if version != 1 {
            return Err(CidError::UnsupportedVersion(version as u8));
        }

        let codec = read_varint(bytes, &mut pos)?;
        let hash_code = read_varint(bytes, &mut pos)?;
        let digest_len = read_varint(bytes, &mut pos)? as usize;

        if pos + digest_len > bytes.len() {
            return Err(CidError::Invalid(format!(
                "CID bytes too short: need {} more bytes, have {}",
                digest_len,
                bytes.len() - pos
            )));
        }

        let digest = bytes[pos..pos + digest_len].to_vec();

        Ok(Cid {
            version: version as u8,
            codec,
            hash_code,
            digest,
        })
    }

    /// Parse a CID from a multibase-encoded string.
    ///
    /// CIDv1 strings use base32lower by default (prefix 'b').
    pub fn from_str_multibase(s: &str) -> Result<Self, CidError> {
        if s.is_empty() {
            return Err(CidError::Invalid("Empty CID string".to_string()));
        }

        let (_, bytes) =
            multibase::decode(s).map_err(|e| CidError::MultibaseDecode(e.to_string()))?;

        Self::from_bytes(&bytes)
    }

    /// Encode this CID as a multibase string (base32lower, prefix 'b').
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
        Cid::from_str_multibase(s)
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
        Cid::from_str_multibase(&s).map_err(serde::de::Error::custom)
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

        value |= ((byte & 0x7F) as u64) << shift;

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
            digest: vec![0; 32],
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
}
