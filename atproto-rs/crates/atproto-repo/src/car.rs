//! CAR (Content Addressable aRchive) file reading and writing.
//!
//! CAR format:
//! 1. Header (CBOR): { version: 1, roots: [CID] }
//! 2. Blocks (repeated): varint(len) + CID bytes + block data

use std::collections::BTreeMap;

use atproto_lex_data::{Cid, LexValue};

use crate::block_map::BlockMap;
use crate::error::RepoError;

/// A single block in a CAR file.
#[derive(Debug, Clone)]
pub struct CarBlock {
    pub cid: Cid,
    pub bytes: Vec<u8>,
}

/// Write a CAR file from a root CID and a BlockMap.
pub fn blocks_to_car(root: Option<&Cid>, blocks: &BlockMap) -> Result<Vec<u8>, RepoError> {
    let mut output = Vec::new();

    // Encode header
    let roots = match root {
        Some(cid) => vec![LexValue::Cid(cid.clone())],
        None => vec![],
    };
    let mut header_map = BTreeMap::new();
    header_map.insert("version".to_string(), LexValue::Integer(1));
    header_map.insert("roots".to_string(), LexValue::Array(roots));
    let header_value = LexValue::Map(header_map);
    let header_bytes = atproto_lex_cbor::encode(&header_value)?;

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

/// Read a CAR file, returning roots and a BlockMap.
pub fn read_car(data: &[u8]) -> Result<(Vec<Cid>, BlockMap), RepoError> {
    let mut pos = 0;

    // Read header
    let header_len = read_varint(data, &mut pos)? as usize;
    if pos + header_len > data.len() {
        return Err(RepoError::Car("Header extends beyond data".into()));
    }
    let header_bytes = &data[pos..pos + header_len];
    pos += header_len;

    let header_value = atproto_lex_cbor::decode(header_bytes)?;
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
        let block_len = read_varint(data, &mut pos)? as usize;
        if pos + block_len > data.len() {
            return Err(RepoError::Car("Block extends beyond data".into()));
        }

        let block_data = &data[pos..pos + block_len];
        pos += block_len;

        // Parse CID from the front of block_data
        let (cid, cid_len) = parse_cid_from_bytes(block_data)?;
        let value_bytes = block_data[cid_len..].to_vec();

        blocks.set(cid, value_bytes);
    }

    Ok((roots, blocks))
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
    let digest_size = read_varint_from_slice(data, &mut pos)? as usize;
    if pos + digest_size > data.len() {
        return Err(RepoError::Car("CID digest extends beyond data".into()));
    }
    pos += digest_size;

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
        result |= ((byte & 0x7F) as u64) << shift;
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
        } else {
            buf.push(byte | 0x80);
        }
    }
}

/// Read an unsigned varint from data at position.
fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, RepoError> {
    read_varint_from_slice(data, pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_lex_data::LexValue;

    fn make_cid(data: &str) -> Cid {
        atproto_lex_cbor::cid_for_lex(&LexValue::String(data.into())).unwrap()
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
        let bytes = atproto_lex_cbor::encode(&val).unwrap();
        let cid = blocks.add_value(&val).unwrap();

        let car = blocks_to_car(Some(&cid), &blocks).unwrap();
        let (_, decoded) = read_car(&car).unwrap();

        let decoded_bytes = decoded.get(&cid).unwrap();
        assert_eq!(decoded_bytes, bytes.as_slice());
    }

    #[test]
    fn car_multiple_blocks() {
        let mut blocks = BlockMap::new();
        for i in 0..10 {
            blocks
                .add_value(&LexValue::String(format!("block {i}").into()))
                .unwrap();
        }

        let root = make_cid("root");
        let car = blocks_to_car(Some(&root), &blocks).unwrap();
        let (roots, decoded) = read_car(&car).unwrap();

        assert_eq!(roots.len(), 1);
        assert_eq!(decoded.len(), 10);
    }
}
