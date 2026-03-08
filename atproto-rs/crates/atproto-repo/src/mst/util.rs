//! MST utility functions — hashing, key validation, node serialization.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use proto_blue_lex_data::{Cid, LexValue};

use crate::error::RepoError;

/// Count leading zeros in a SHA-256 hash of the key, using 2-bit (base-4) chunks.
///
/// This determines which layer a key belongs to in the MST.
/// Approximately 1/4 of keys will have at least 1 leading zero,
/// giving the tree a ~4-way fanout.
pub fn leading_zeros_on_hash(key: &str) -> usize {
    let hash = Sha256::digest(key.as_bytes());
    let mut total = 0;
    for &byte in &hash[..] {
        // Check each 2-bit pair from MSB
        if byte >> 6 == 0 {
            total += 1;
        } else {
            return total;
        }
        if (byte >> 4) & 0x03 == 0 {
            total += 1;
        } else {
            return total;
        }
        if (byte >> 2) & 0x03 == 0 {
            total += 1;
        } else {
            return total;
        }
        if byte & 0x03 == 0 {
            total += 1;
        } else {
            return total;
        }
    }
    total
}

/// Count the common prefix length between two strings.
pub fn count_prefix_len(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
}

/// Check if a string is a valid MST key.
///
/// Valid MST keys have the format `collection/rkey`, with only
/// allowed characters: a-z, A-Z, 0-9, _, ~, -, :, .
pub fn is_valid_mst_key(key: &str) -> bool {
    if key.len() > 1024 {
        return false;
    }
    let parts: Vec<&str> = key.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    if parts[0].is_empty() || parts[1].is_empty() {
        return false;
    }
    is_valid_chars(key)
}

fn is_valid_chars(s: &str) -> bool {
    s.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || b == b'_'
            || b == b'~'
            || b == b'-'
            || b == b':'
            || b == b'.'
            || b == b'/'
    })
}

/// Ensure a key is valid, returning an error if not.
pub fn ensure_valid_mst_key(key: &str) -> Result<(), RepoError> {
    if !is_valid_mst_key(key) {
        return Err(RepoError::InvalidMstKey(key.to_string()));
    }
    Ok(())
}

/// An entry in an MST node's CBOR-encoded entry list.
#[derive(Debug, Clone)]
pub struct TreeEntry {
    /// Prefix length shared with previous key.
    pub prefix_len: usize,
    /// Key suffix (the part after the shared prefix).
    pub key_suffix: Vec<u8>,
    /// Value CID (the record this key points to).
    pub value: Cid,
    /// Optional right subtree CID (subtree after this entry).
    pub tree: Option<Cid>,
}

/// CBOR-encoded MST node data.
#[derive(Debug, Clone)]
pub struct NodeData {
    /// Left-most subtree pointer (before all entries).
    pub left: Option<Cid>,
    /// Entries with prefix-compressed keys.
    pub entries: Vec<TreeEntry>,
}

/// Serialize NodeData to a LexValue for CBOR encoding.
pub fn serialize_node_data(data: &NodeData) -> LexValue {
    let mut entries_arr = Vec::new();
    for entry in &data.entries {
        let mut e_map = BTreeMap::new();
        e_map.insert("p".to_string(), LexValue::Integer(entry.prefix_len as i64));
        e_map.insert("k".to_string(), LexValue::Bytes(entry.key_suffix.clone()));
        e_map.insert("v".to_string(), LexValue::Cid(entry.value.clone()));
        if let Some(t) = &entry.tree {
            e_map.insert("t".to_string(), LexValue::Cid(t.clone()));
        }
        entries_arr.push(LexValue::Map(e_map));
    }

    let mut node_map = BTreeMap::new();
    if let Some(left) = &data.left {
        node_map.insert("l".to_string(), LexValue::Cid(left.clone()));
    } else {
        node_map.insert("l".to_string(), LexValue::Null);
    }
    node_map.insert("e".to_string(), LexValue::Array(entries_arr));
    LexValue::Map(node_map)
}

/// Deserialize NodeData from a LexValue (decoded from CBOR).
pub fn deserialize_node_data(value: &LexValue) -> Result<NodeData, RepoError> {
    let map = value
        .as_map()
        .ok_or_else(|| RepoError::InvalidMst("Node data is not a map".into()))?;

    let left = match map.get("l") {
        Some(LexValue::Cid(cid)) => Some(cid.clone()),
        Some(LexValue::Null) | None => None,
        _ => return Err(RepoError::InvalidMst("Invalid left pointer".into())),
    };

    let entries_val = map
        .get("e")
        .and_then(|v| v.as_array())
        .ok_or_else(|| RepoError::InvalidMst("Missing entries array".into()))?;

    let mut entries = Vec::new();
    for entry_val in entries_val {
        let e_map = entry_val
            .as_map()
            .ok_or_else(|| RepoError::InvalidMst("Entry is not a map".into()))?;

        let prefix_len = e_map
            .get("p")
            .and_then(|v| v.as_integer())
            .ok_or_else(|| RepoError::InvalidMst("Missing prefix length".into()))?
            as usize;

        let key_suffix = e_map
            .get("k")
            .and_then(|v| v.as_bytes())
            .ok_or_else(|| RepoError::InvalidMst("Missing key suffix".into()))?
            .to_vec();

        let value = e_map
            .get("v")
            .and_then(|v| v.as_cid())
            .ok_or_else(|| RepoError::InvalidMst("Missing value CID".into()))?
            .clone();

        let tree = match e_map.get("t") {
            Some(LexValue::Cid(cid)) => Some(cid.clone()),
            _ => None,
        };

        entries.push(TreeEntry {
            prefix_len,
            key_suffix,
            value,
            tree,
        });
    }

    Ok(NodeData { left, entries })
}

/// Reconstruct full keys from prefix-compressed entries.
pub fn entries_to_keys(data: &NodeData) -> Vec<String> {
    let mut keys = Vec::new();
    let mut last_key = String::new();
    for entry in &data.entries {
        let prefix = &last_key[..entry.prefix_len.min(last_key.len())];
        let suffix = String::from_utf8_lossy(&entry.key_suffix);
        let key = format!("{prefix}{suffix}");
        last_key = key.clone();
        keys.push(key);
    }
    keys
}

/// Compute the CID for a serialized node.
pub fn cid_for_entries(data: &NodeData) -> Result<Cid, RepoError> {
    let value = serialize_node_data(data);
    Ok(proto_blue_lex_cbor::cid_for_lex(&value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zeros_basic() {
        // Leading zeros is deterministic based on SHA-256 hash
        let z = leading_zeros_on_hash("test");
        // Just verify it returns a reasonable value (0-128)
        assert!(z <= 128);
    }

    #[test]
    fn leading_zeros_deterministic() {
        let z1 = leading_zeros_on_hash("app.bsky.feed.post/abc123");
        let z2 = leading_zeros_on_hash("app.bsky.feed.post/abc123");
        assert_eq!(z1, z2);
    }

    #[test]
    fn leading_zeros_distribution() {
        // Most keys should have 0 zeros (75% chance)
        let mut zero_count = 0;
        let total = 1000;
        for i in 0..total {
            if leading_zeros_on_hash(&format!("app.bsky.feed.post/{i}")) == 0 {
                zero_count += 1;
            }
        }
        // Should be roughly 750 +/- some variance
        assert!(
            zero_count > 600 && zero_count < 900,
            "zero_count={zero_count}"
        );
    }

    #[test]
    fn prefix_len_counting() {
        assert_eq!(count_prefix_len("abc", "abd"), 2);
        assert_eq!(count_prefix_len("abc", "abc"), 3);
        assert_eq!(count_prefix_len("abc", "xyz"), 0);
        assert_eq!(count_prefix_len("", "abc"), 0);
    }

    #[test]
    fn valid_mst_keys() {
        assert!(is_valid_mst_key("app.bsky.feed.post/abc123"));
        assert!(is_valid_mst_key("com.example/self"));
        assert!(is_valid_mst_key("a/b"));
    }

    #[test]
    fn invalid_mst_keys() {
        assert!(!is_valid_mst_key("")); // Empty
        assert!(!is_valid_mst_key("noSlash")); // No slash
        assert!(!is_valid_mst_key("a/b/c")); // Too many slashes
        assert!(!is_valid_mst_key("/b")); // Empty collection
        assert!(!is_valid_mst_key("a/")); // Empty rkey
        assert!(!is_valid_mst_key("a/b c")); // Space
    }

    #[test]
    fn node_data_roundtrip() {
        let cid1 = proto_blue_lex_cbor::cid_for_lex(&LexValue::String("val1".into())).unwrap();
        let cid2 = proto_blue_lex_cbor::cid_for_lex(&LexValue::String("val2".into())).unwrap();

        let data = NodeData {
            left: None,
            entries: vec![
                TreeEntry {
                    prefix_len: 0,
                    key_suffix: b"app.bsky.feed.post/abc".to_vec(),
                    value: cid1,
                    tree: None,
                },
                TreeEntry {
                    prefix_len: 19,
                    key_suffix: b"def".to_vec(),
                    value: cid2,
                    tree: None,
                },
            ],
        };

        // Serialize to LexValue and back
        let lex = serialize_node_data(&data);
        let decoded = deserialize_node_data(&lex).unwrap();
        assert_eq!(decoded.entries.len(), 2);
        assert!(decoded.left.is_none());

        // Verify key reconstruction
        let keys = entries_to_keys(&decoded);
        assert_eq!(keys[0], "app.bsky.feed.post/abc");
        assert_eq!(keys[1], "app.bsky.feed.post/def");
    }

    #[test]
    fn node_data_with_left_subtree() {
        let cid = proto_blue_lex_cbor::cid_for_lex(&LexValue::String("val".into())).unwrap();
        let left_cid = proto_blue_lex_cbor::cid_for_lex(&LexValue::String("left".into())).unwrap();

        let data = NodeData {
            left: Some(left_cid.clone()),
            entries: vec![TreeEntry {
                prefix_len: 0,
                key_suffix: b"a/b".to_vec(),
                value: cid,
                tree: None,
            }],
        };

        let lex = serialize_node_data(&data);
        let decoded = deserialize_node_data(&lex).unwrap();
        assert_eq!(
            decoded.left.unwrap().to_string_base32(),
            left_cid.to_string_base32()
        );
    }

    #[test]
    fn cid_for_entries_deterministic() {
        let cid_val = proto_blue_lex_cbor::cid_for_lex(&LexValue::String("val".into())).unwrap();
        let data = NodeData {
            left: None,
            entries: vec![TreeEntry {
                prefix_len: 0,
                key_suffix: b"a/b".to_vec(),
                value: cid_val,
                tree: None,
            }],
        };

        let cid1 = cid_for_entries(&data).unwrap();
        let cid2 = cid_for_entries(&data).unwrap();
        assert_eq!(cid1.to_string_base32(), cid2.to_string_base32());
    }
}
