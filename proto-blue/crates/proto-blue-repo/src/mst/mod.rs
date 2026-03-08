//! Merkle Search Tree implementation for AT Protocol repositories.

pub mod node;
pub mod util;

pub use node::{Leaf, MstNode, NodeEntry};
pub use util::{
    NodeData, TreeEntry, cid_for_entries, count_prefix_len, deserialize_node_data,
    ensure_valid_mst_key, entries_to_keys, is_valid_mst_key, leading_zeros_on_hash,
    serialize_node_data,
};
