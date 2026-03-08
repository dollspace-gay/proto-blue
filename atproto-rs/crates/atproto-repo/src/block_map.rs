//! BlockMap — a map from CID to block bytes.

use std::collections::HashMap;

use proto_blue_lex_data::{Cid, LexValue};

use crate::error::RepoError;

/// A map from CID to block bytes.
///
/// Internally stores CIDs as base32 strings for efficient lookup.
#[derive(Debug, Clone, Default)]
pub struct BlockMap {
    map: HashMap<String, (Cid, Vec<u8>)>,
}

impl BlockMap {
    /// Create a new empty block map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a LexValue, encoding it as CBOR and computing its CID.
    pub fn add_value(&mut self, value: &LexValue) -> Result<Cid, RepoError> {
        let bytes = proto_blue_lex_cbor::encode(value)?;
        let cid = proto_blue_lex_cbor::cid_for_lex(value)?;
        self.set(cid.clone(), bytes);
        Ok(cid)
    }

    /// Set a block by CID.
    pub fn set(&mut self, cid: Cid, bytes: Vec<u8>) {
        let key = cid.to_string_base32();
        self.map.insert(key, (cid, bytes));
    }

    /// Get block bytes by CID.
    pub fn get(&self, cid: &Cid) -> Option<&[u8]> {
        self.map
            .get(&cid.to_string_base32())
            .map(|(_, b)| b.as_slice())
    }

    /// Check if a CID exists in the map.
    pub fn has(&self, cid: &Cid) -> bool {
        self.map.contains_key(&cid.to_string_base32())
    }

    /// Remove a block by CID.
    pub fn delete(&mut self, cid: &Cid) {
        self.map.remove(&cid.to_string_base32());
    }

    /// Get multiple blocks. Returns found blocks and missing CIDs.
    pub fn get_many(&self, cids: &[Cid]) -> (BlockMap, Vec<Cid>) {
        let mut found = BlockMap::new();
        let mut missing = Vec::new();
        for cid in cids {
            if let Some(bytes) = self.get(cid) {
                found.set(cid.clone(), bytes.to_vec());
            } else {
                missing.push(cid.clone());
            }
        }
        (found, missing)
    }

    /// Merge another BlockMap into this one.
    pub fn add_map(&mut self, other: &BlockMap) {
        for (key, (cid, bytes)) in &other.map {
            self.map.insert(key.clone(), (cid.clone(), bytes.clone()));
        }
    }

    /// Get the number of blocks.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Check if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Get the total byte size of all blocks.
    pub fn byte_size(&self) -> usize {
        self.map.values().map(|(_, b)| b.len()).sum()
    }

    /// Clear all blocks.
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Iterate over all (CID, bytes) entries.
    pub fn iter(&self) -> impl Iterator<Item = (&Cid, &[u8])> {
        self.map
            .values()
            .map(|(cid, bytes)| (cid, bytes.as_slice()))
    }

    /// Get all CIDs.
    pub fn cids(&self) -> Vec<Cid> {
        self.map.values().map(|(cid, _)| cid.clone()).collect()
    }

    /// Consume the map and iterate over owned entries.
    pub fn into_entries(self) -> impl Iterator<Item = (Cid, Vec<u8>)> {
        self.map.into_values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_value() -> LexValue {
        LexValue::String("hello world".into())
    }

    #[test]
    fn add_and_get() {
        let mut map = BlockMap::new();
        let cid = map.add_value(&test_value()).unwrap();
        assert!(map.has(&cid));
        assert!(map.get(&cid).is_some());
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn delete_block() {
        let mut map = BlockMap::new();
        let cid = map.add_value(&test_value()).unwrap();
        map.delete(&cid);
        assert!(!map.has(&cid));
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn merge_maps() {
        let mut map1 = BlockMap::new();
        let mut map2 = BlockMap::new();
        let cid1 = map1.add_value(&LexValue::String("a".into())).unwrap();
        let cid2 = map2.add_value(&LexValue::String("b".into())).unwrap();

        map1.add_map(&map2);
        assert!(map1.has(&cid1));
        assert!(map1.has(&cid2));
        assert_eq!(map1.len(), 2);
    }

    #[test]
    fn get_many_blocks() {
        let mut map = BlockMap::new();
        let cid1 = map.add_value(&LexValue::String("a".into())).unwrap();
        let cid2 = map.add_value(&LexValue::String("b".into())).unwrap();
        let cid3 = proto_blue_lex_cbor::cid_for_lex(&LexValue::String("missing".into())).unwrap();

        let (found, missing) = map.get_many(&[cid1.clone(), cid2.clone(), cid3.clone()]);
        assert_eq!(found.len(), 2);
        assert_eq!(missing.len(), 1);
        assert!(found.has(&cid1));
        assert!(found.has(&cid2));
    }

    #[test]
    fn byte_size() {
        let mut map = BlockMap::new();
        map.add_value(&LexValue::String("hello".into())).unwrap();
        assert!(map.byte_size() > 0);
    }
}
