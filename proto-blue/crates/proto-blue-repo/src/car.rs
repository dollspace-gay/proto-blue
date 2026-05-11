//! CAR (Content Addressable aRchive) file reading and writing.
//!
//! CAR format:
//! 1. Header (CBOR): `{ version: 1, roots: [CID] }`
//! 2. Blocks (repeated): `varint(len) + CID bytes + block data`
//!
//! # CID verification on read
//!
//! [`read_car`] hashes each block's payload and confirms the declared
//! CID matches. A mismatch returns [`RepoError::CidMismatch`]. This
//! matches TS `@atproto/repo`'s `verifyIncomingCarBlocks` behaviour —
//! skipping the check would defeat content-addressed storage (a
//! malicious CAR could feed blocks whose CIDs don't match their
//! bytes, and the downstream verifier would trust them).
//!
//! Callers whose blocks have already been verified upstream can use
//! [`read_car_opts`] with [`ReadCarOpts::skip_cid_verification`] to
//! bypass the check.

use std::collections::BTreeMap;

use proto_blue_lex_data::{Cid, LexValue};

use crate::block_map::BlockMap;
use crate::error::RepoError;

/// A single block in a CAR file.
#[derive(Debug, Clone)]
pub struct CarBlock {
    pub cid: Cid,
    pub bytes: Vec<u8>,
}

/// Options for [`read_car_opts`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadCarOpts {
    /// When `true`, do not verify that each block's declared CID
    /// matches the SHA-256 hash of its bytes. Defaults to `false`.
    ///
    /// Only set this when the caller has already verified CIDs
    /// upstream; otherwise a malicious/corrupt CAR can silently
    /// inject blocks whose CIDs lie about their contents.
    pub skip_cid_verification: bool,
}

/// Write a CAR file from a root CID and a `BlockMap`.
pub fn blocks_to_car(root: Option<&Cid>, blocks: &BlockMap) -> Result<Vec<u8>, RepoError> {
    let mut output = Vec::new();

    // Encode header
    let roots = root.map_or_else(Vec::new, |cid| vec![LexValue::Cid(cid.clone())]);
    let mut header_map = BTreeMap::new();
    header_map.insert("version".to_string(), LexValue::Integer(1));
    header_map.insert("roots".to_string(), LexValue::Array(roots));
    let header_value = LexValue::Map(header_map);
    let header_bytes = proto_blue_lex_cbor::encode(&header_value)?;

    // Write header length varint + header
    write_varint(&mut output, header_bytes.len() as u64);
    output.extend_from_slice(&header_bytes);

    // Write each block: varint(cid_bytes.len + block_bytes.len) + cid_bytes + block_bytes
    for (cid, bytes) in blocks.iter() {
        let cid_bytes = cid.to_bytes();
        let total_len = cid_bytes.len() + bytes.len();
        write_varint(&mut output, total_len as u64);
        output.extend_from_slice(&cid_bytes);
        output.extend_from_slice(bytes);
    }

    Ok(output)
}

/// Read a CAR file with CID-for-bytes verification (default).
///
/// Every block's declared CID is re-hashed against its payload; a
/// mismatch returns [`RepoError::CidMismatch`]. This is the correct
/// default for any CAR received over the wire.
pub fn read_car(data: &[u8]) -> Result<(Vec<Cid>, BlockMap), RepoError> {
    read_car_opts(data, ReadCarOpts::default())
}

/// Read a CAR file with caller-supplied options.
///
/// Use `ReadCarOpts { skip_cid_verification: true }` only when the
/// caller has already verified CIDs upstream.
pub fn read_car_opts(data: &[u8], opts: ReadCarOpts) -> Result<(Vec<Cid>, BlockMap), RepoError> {
    let mut pos = 0;

    // Read header. `checked_add` guards against adversarial lengths
    // that would overflow `usize` — the plain `pos + header_len`
    // would panic in debug builds and wrap silently in release. The
    // bound must also not exceed `data.len()` (the "header extends
    // beyond data" case).
    let header_len = usize::try_from(read_varint(data, &mut pos)?)
        .map_err(|_| RepoError::Car("Header length exceeds usize".into()))?;
    let header_end = pos
        .checked_add(header_len)
        .ok_or_else(|| RepoError::Car("Header length overflows usize".into()))?;
    if header_end > data.len() {
        return Err(RepoError::Car("Header extends beyond data".into()));
    }
    let header_bytes = &data[pos..header_end];
    pos = header_end;

    let header_value = proto_blue_lex_cbor::decode(header_bytes)?;
    let header_map = header_value
        .as_map()
        .ok_or_else(|| RepoError::Car("Header is not a map".into()))?;

    // Parse roots
    let roots_val = header_map
        .get("roots")
        .and_then(|v| v.as_array())
        .ok_or_else(|| RepoError::Car("Missing roots array".into()))?;
    let mut roots = Vec::new();
    for root in roots_val {
        let cid = root
            .as_cid()
            .ok_or_else(|| RepoError::Car("Root is not a CID".into()))?;
        roots.push(cid.clone());
    }

    // Read blocks
    let mut blocks = BlockMap::new();
    while pos < data.len() {
        let block_len = usize::try_from(read_varint(data, &mut pos)?)
            .map_err(|_| RepoError::Car("Block length exceeds usize".into()))?;
        let block_end = pos
            .checked_add(block_len)
            .ok_or_else(|| RepoError::Car("Block length overflows usize".into()))?;
        if block_end > data.len() {
            return Err(RepoError::Car("Block extends beyond data".into()));
        }

        let block_data = &data[pos..block_end];
        pos = block_end;

        // Parse CID from the front of block_data
        let (cid, cid_len) = parse_cid_from_bytes(block_data)?;
        let value_bytes = &block_data[cid_len..];

        // Verify CID-for-bytes unless the caller explicitly opted out.
        // A CAR from an untrusted source whose block CIDs don't match
        // their payloads is indistinguishable from corruption / attack
        // — we reject by default.
        if !opts.skip_cid_verification {
            match cid.verify(value_bytes) {
                Ok(true) => {}
                Ok(false) => {
                    let actual = recompute_cid(&cid, value_bytes);
                    return Err(RepoError::CidMismatch {
                        declared: cid.to_string(),
                        actual,
                    });
                }
                Err(e) => {
                    // Unsupported hash function (e.g. SHA-512 for now).
                    // Don't trust the block if we can't verify it.
                    return Err(RepoError::Car(format!("Cannot verify CID {cid}: {e}")));
                }
            }
        }

        blocks.set(cid, value_bytes.to_vec());
    }

    Ok((roots, blocks))
}

/// Compute what the declared CID _would_ be for a given payload, so
/// the mismatch error message can surface both values. Falls back to
/// the string `"<unknown>"` if the original CID's hash function isn't
/// supported for recompute.
fn recompute_cid(declared: &Cid, bytes: &[u8]) -> String {
    use proto_blue_lex_data::{CBOR_CODEC, RAW_CODEC};
    match declared.codec {
        CBOR_CODEC => Cid::for_cbor(bytes).to_string(),
        RAW_CODEC => Cid::for_raw(bytes).to_string(),
        _ => "<unknown>".to_string(),
    }
}

/// Read a CAR file expecting exactly one root.
pub fn read_car_with_root(data: &[u8]) -> Result<(Cid, BlockMap), RepoError> {
    let (roots, blocks) = read_car(data)?;
    if roots.len() != 1 {
        return Err(RepoError::Car(format!(
            "Expected 1 root, got {}",
            roots.len()
        )));
    }
    Ok((roots.into_iter().next().unwrap(), blocks))
}

/// Parse a CID from the beginning of a byte slice.
/// Returns the CID and the number of bytes consumed.
fn parse_cid_from_bytes(data: &[u8]) -> Result<(Cid, usize), RepoError> {
    // CIDv1: multibase-free, starts with version varint, codec varint, multihash
    if data.is_empty() {
        return Err(RepoError::Car("Empty CID data".into()));
    }

    let mut pos = 0;

    // Version varint
    let version = read_varint_from_slice(data, &mut pos)?;
    if version != 1 {
        return Err(RepoError::Car(format!(
            "Unsupported CID version: {version}"
        )));
    }

    // Codec varint
    let _codec = read_varint_from_slice(data, &mut pos)?;

    // Multihash: hash function varint + digest size varint + digest bytes
    let _hash_fn = read_varint_from_slice(data, &mut pos)?;
    let digest_size = usize::try_from(read_varint_from_slice(data, &mut pos)?)
        .map_err(|_| RepoError::Car("CID digest size exceeds usize".into()))?;
    let digest_end = pos
        .checked_add(digest_size)
        .ok_or_else(|| RepoError::Car("CID digest length overflows usize".into()))?;
    if digest_end > data.len() {
        return Err(RepoError::Car("CID digest extends beyond data".into()));
    }
    pos = digest_end;

    let cid =
        Cid::from_bytes(&data[..pos]).map_err(|e| RepoError::Car(format!("Invalid CID: {e}")))?;

    Ok((cid, pos))
}

fn read_varint_from_slice(data: &[u8], pos: &mut usize) -> Result<u64, RepoError> {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        if *pos >= data.len() {
            return Err(RepoError::Car("Unexpected end of varint".into()));
        }
        let byte = data[*pos];
        *pos += 1;
        result |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err(RepoError::Car("Varint too large".into()));
        }
    }
}

/// Write an unsigned varint to a buffer.
fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

/// Read an unsigned varint from data at position.
fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, RepoError> {
    read_varint_from_slice(data, pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_blue_lex_data::LexValue;

    fn make_cid(data: &str) -> Cid {
        proto_blue_lex_cbor::cid_for_lex(&LexValue::String(data.into())).unwrap()
    }

    #[test]
    fn varint_roundtrip() {
        for &val in &[0u64, 1, 127, 128, 255, 256, 16383, 16384, 100000] {
            let mut buf = Vec::new();
            write_varint(&mut buf, val);
            let mut pos = 0;
            let decoded = read_varint(&buf, &mut pos).unwrap();
            assert_eq!(decoded, val, "varint roundtrip failed for {val}");
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn car_roundtrip_empty() {
        let blocks = BlockMap::new();
        let car = blocks_to_car(None, &blocks).unwrap();
        let (roots, decoded) = read_car(&car).unwrap();
        assert!(roots.is_empty());
        assert_eq!(decoded.len(), 0);
    }

    #[test]
    fn car_roundtrip_with_blocks() {
        let mut blocks = BlockMap::new();
        let val1 = LexValue::String("hello".into());
        let val2 = LexValue::String("world".into());
        let cid1 = blocks.add_value(&val1).unwrap();
        let cid2 = blocks.add_value(&val2).unwrap();

        let car = blocks_to_car(Some(&cid1), &blocks).unwrap();
        let (roots, decoded) = read_car(&car).unwrap();

        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].to_string_base32(), cid1.to_string_base32());
        assert_eq!(decoded.len(), 2);
        assert!(decoded.has(&cid1));
        assert!(decoded.has(&cid2));
    }

    #[test]
    fn read_car_with_root_single() {
        let mut blocks = BlockMap::new();
        let cid = blocks.add_value(&LexValue::String("test".into())).unwrap();

        let car = blocks_to_car(Some(&cid), &blocks).unwrap();
        let (root, decoded) = read_car_with_root(&car).unwrap();
        assert_eq!(root.to_string_base32(), cid.to_string_base32());
        assert_eq!(decoded.len(), 1);
    }

    #[test]
    fn car_preserves_block_content() {
        let mut blocks = BlockMap::new();
        let val = LexValue::String("test data".into());
        let bytes = proto_blue_lex_cbor::encode(&val).unwrap();
        let cid = blocks.add_value(&val).unwrap();

        let car = blocks_to_car(Some(&cid), &blocks).unwrap();
        let (_, decoded) = read_car(&car).unwrap();

        let decoded_bytes = decoded.get(&cid).unwrap();
        assert_eq!(decoded_bytes, bytes.as_slice());
    }

    #[test]
    fn read_car_rejects_cid_mismatch() {
        use crate::block_map::BlockMap;

        // Build a well-formed CAR, then construct a byte buffer whose
        // block payload has been tampered — declared CID no longer
        // matches the actual bytes.
        let mut blocks = BlockMap::new();
        let honest_cid = blocks
            .add_value(&LexValue::String("honest".into()))
            .unwrap();
        let tampered_bytes =
            proto_blue_lex_cbor::encode(&LexValue::String("tampered".into())).unwrap();

        // Manually frame: header + (varint(cid_bytes + payload_len) + cid_bytes + tampered_bytes)
        let header_value = LexValue::Map({
            let mut m = BTreeMap::new();
            m.insert("version".to_string(), LexValue::Integer(1));
            m.insert(
                "roots".to_string(),
                LexValue::Array(vec![LexValue::Cid(honest_cid.clone())]),
            );
            m
        });
        let header_bytes = proto_blue_lex_cbor::encode(&header_value).unwrap();

        let mut car = Vec::new();
        write_varint(&mut car, header_bytes.len() as u64);
        car.extend_from_slice(&header_bytes);

        let cid_bytes = honest_cid.to_bytes();
        let total_len = cid_bytes.len() + tampered_bytes.len();
        write_varint(&mut car, total_len as u64);
        car.extend_from_slice(&cid_bytes);
        car.extend_from_slice(&tampered_bytes);

        // Default read rejects the mismatch.
        let err = read_car(&car).unwrap_err();
        match &err {
            RepoError::CidMismatch { declared, actual } => {
                assert_eq!(declared, &honest_cid.to_string());
                assert_ne!(declared, actual);
            }
            other => panic!("expected CidMismatch, got: {other:?}"),
        }

        // Opt-out accepts the tampered block (the caller said they'd
        // already verified upstream).
        let opts = ReadCarOpts {
            skip_cid_verification: true,
        };
        let (_, decoded) = read_car_opts(&car, opts).unwrap();
        assert!(decoded.has(&honest_cid));
    }

    #[test]
    fn car_multiple_blocks() {
        let mut blocks = BlockMap::new();
        for i in 0..10 {
            blocks
                .add_value(&LexValue::String(format!("block {i}")))
                .unwrap();
        }

        let root = make_cid("root");
        let car = blocks_to_car(Some(&root), &blocks).unwrap();
        let (roots, decoded) = read_car(&car).unwrap();

        assert_eq!(roots.len(), 1);
        assert_eq!(decoded.len(), 10);
    }

    /// Regression for the fuzz-found integer overflow on adversarial
    /// header lengths. The original bounds check was
    /// `pos + header_len > data.len()`, which panics in debug when
    /// `pos + header_len` overflows `usize`. Replaced with
    /// `checked_add`; this input is the shrunk libFuzzer reproducer
    /// that hit the panic.
    #[test]
    fn car_rejects_overflowing_header_length() {
        // A single varint encoding `usize::MAX` followed by no bytes.
        // The 10-byte continuation varint `0xFF,0xFF,...,0x01` decodes
        // to 2^63 on 64-bit (first bit of the tenth byte). Any value
        // large enough that `pos + header_len` overflows is sufficient
        // — we just want to exercise the checked_add arm.
        let adversarial: Vec<u8> = vec![0xff; 10]
            .into_iter()
            .chain(std::iter::once(0x01))
            .collect();
        let err = read_car(&adversarial).unwrap_err();
        // Acceptable outcomes: any RepoError (varint overflow, usize
        // overflow in the bounds check, or "extends beyond data").
        // The important property is: no panic.
        assert!(
            matches!(err, RepoError::Car(_)),
            "expected a Car error, got {err:?}"
        );
    }
}
