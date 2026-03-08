//! MST (Merkle Search Tree) implementation.
//!
//! An ordered, insertion-order-independent, deterministic tree for storing
//! key-value pairs where keys are `collection/rkey` paths and values are CIDs.

use proto_blue_lex_data::Cid;

use crate::block_map::BlockMap;
use crate::cid_set::CidSet;
use crate::error::RepoError;
use crate::mst::util::*;

/// A leaf entry in the MST — a key-value pair.
#[derive(Debug, Clone)]
pub struct Leaf {
    pub key: String,
    pub value: Cid,
}

/// An entry in the MST: either a subtree or a leaf.
#[derive(Debug, Clone)]
pub enum NodeEntry {
    Leaf(Leaf),
    Tree(MstNode),
}

impl NodeEntry {
    pub fn is_leaf(&self) -> bool {
        matches!(self, NodeEntry::Leaf(_))
    }

    pub fn is_tree(&self) -> bool {
        matches!(self, NodeEntry::Tree(_))
    }

    pub fn as_leaf(&self) -> Option<&Leaf> {
        match self {
            NodeEntry::Leaf(l) => Some(l),
            _ => None,
        }
    }
}

/// An MST node, which can be either loaded (entries in memory) or
/// a lazy pointer (just a CID, entries loaded on demand from storage).
#[derive(Debug, Clone)]
pub struct MstNode {
    /// The entries in this node (if loaded).
    entries: Vec<NodeEntry>,
    /// The layer this node is at (determined by first leaf key).
    layer: Option<usize>,
    /// Cached CID (None if entries have been modified).
    pointer: Option<Cid>,
}

impl MstNode {
    /// Create a new empty MST node.
    pub fn empty() -> Self {
        MstNode {
            entries: Vec::new(),
            layer: Some(0),
            pointer: None,
        }
    }

    /// Create an MST node from entries.
    pub fn from_entries(entries: Vec<NodeEntry>) -> Self {
        let layer = Self::detect_layer(&entries);
        MstNode {
            entries,
            layer,
            pointer: None,
        }
    }

    /// Create an MST node from a CID and loaded NodeData.
    pub fn from_data(data: &NodeData, blocks: &BlockMap) -> Result<Self, RepoError> {
        let entries = Self::deserialize_entries(data, blocks)?;
        let layer = Self::detect_layer(&entries);
        Ok(MstNode {
            entries,
            layer,
            pointer: None,
        })
    }

    /// Load an MST from a root CID.
    pub fn load(cid: &Cid, blocks: &BlockMap) -> Result<Self, RepoError> {
        let bytes = blocks
            .get(cid)
            .ok_or_else(|| RepoError::MissingBlock(cid.clone()))?;
        let value = proto_blue_lex_cbor::decode(bytes)?;
        let data = deserialize_node_data(&value)?;
        let mut node = Self::from_data(&data, blocks)?;
        node.pointer = Some(cid.clone());
        Ok(node)
    }

    fn detect_layer(entries: &[NodeEntry]) -> Option<usize> {
        for entry in entries {
            if let NodeEntry::Leaf(leaf) = entry {
                return Some(leading_zeros_on_hash(&leaf.key));
            }
        }
        None
    }

    fn deserialize_entries(
        data: &NodeData,
        blocks: &BlockMap,
    ) -> Result<Vec<NodeEntry>, RepoError> {
        let mut entries = Vec::new();
        let keys = entries_to_keys(data);

        if let Some(left_cid) = &data.left {
            let subtree = MstNode::load(left_cid, blocks)?;
            entries.push(NodeEntry::Tree(subtree));
        }

        for (i, tree_entry) in data.entries.iter().enumerate() {
            entries.push(NodeEntry::Leaf(Leaf {
                key: keys[i].clone(),
                value: tree_entry.value.clone(),
            }));
            if let Some(tree_cid) = &tree_entry.tree {
                let subtree = MstNode::load(tree_cid, blocks)?;
                entries.push(NodeEntry::Tree(subtree));
            }
        }

        Ok(entries)
    }

    /// Get the layer of this node.
    pub fn get_layer(&self) -> usize {
        self.layer.unwrap_or(0)
    }

    /// Get all entries.
    pub fn entries(&self) -> &[NodeEntry] {
        &self.entries
    }

    // -----------------------------------------------------------------------
    // GET
    // -----------------------------------------------------------------------

    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<Cid> {
        for entry in &self.entries {
            match entry {
                NodeEntry::Leaf(leaf) => {
                    if leaf.key == key {
                        return Some(leaf.value.clone());
                    }
                    if leaf.key.as_str() > key {
                        // Keys are sorted; we've passed the target
                        return None;
                    }
                }
                NodeEntry::Tree(subtree) => {
                    if let Some(val) = subtree.get(key) {
                        return Some(val);
                    }
                }
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // ADD
    // -----------------------------------------------------------------------

    /// Add a new key-value pair. Returns error if key already exists.
    pub fn add(&self, key: &str, value: Cid) -> Result<MstNode, RepoError> {
        ensure_valid_mst_key(key)?;
        if self.get(key).is_some() {
            return Err(RepoError::KeyAlreadyExists(key.to_string()));
        }

        let key_zeros = leading_zeros_on_hash(key);
        let layer = self.get_layer();

        if key_zeros == layer {
            self.insert_at_this_layer(key, value)
        } else if key_zeros > layer {
            self.create_parent_layers(key, value, key_zeros)
        } else {
            self.insert_into_child(key, value)
        }
    }

    /// Insert a leaf at this node's layer.
    fn insert_at_this_layer(&self, key: &str, value: Cid) -> Result<MstNode, RepoError> {
        // Find the position to insert. Walk entries and find the right spot.
        let new_leaf = NodeEntry::Leaf(Leaf {
            key: key.to_string(),
            value,
        });

        let mut new_entries = Vec::new();
        let mut inserted = false;

        let mut i = 0;
        while i < self.entries.len() {
            if inserted {
                new_entries.push(self.entries[i].clone());
                i += 1;
                continue;
            }

            match &self.entries[i] {
                NodeEntry::Leaf(leaf) if key < leaf.key.as_str() => {
                    // Insert before this leaf. If prev entry was a tree, split it.
                    if i > 0 {
                        if let Some(NodeEntry::Tree(prev_tree)) = new_entries.last() {
                            let prev_tree = prev_tree.clone();
                            new_entries.pop();
                            let (left, right) = prev_tree.split_around(key);
                            if let Some(l) = left {
                                if !l.entries.is_empty() {
                                    new_entries.push(NodeEntry::Tree(l));
                                }
                            }
                            new_entries.push(new_leaf.clone());
                            if let Some(r) = right {
                                if !r.entries.is_empty() {
                                    new_entries.push(NodeEntry::Tree(r));
                                }
                            }
                        } else {
                            new_entries.push(new_leaf.clone());
                        }
                    } else {
                        new_entries.push(new_leaf.clone());
                    }
                    inserted = true;
                    new_entries.push(self.entries[i].clone());
                    i += 1;
                }
                _ => {
                    new_entries.push(self.entries[i].clone());
                    i += 1;
                }
            }
        }

        if !inserted {
            // Goes at the end. If last entry was a tree, split it.
            if let Some(NodeEntry::Tree(last_tree)) = new_entries.last() {
                let last_tree = last_tree.clone();
                new_entries.pop();
                let (left, right) = last_tree.split_around(key);
                if let Some(l) = left {
                    if !l.entries.is_empty() {
                        new_entries.push(NodeEntry::Tree(l));
                    }
                }
                new_entries.push(new_leaf);
                if let Some(r) = right {
                    if !r.entries.is_empty() {
                        new_entries.push(NodeEntry::Tree(r));
                    }
                }
            } else {
                new_entries.push(new_leaf);
            }
        }

        Ok(MstNode::from_entries(new_entries))
    }

    /// Insert a key that belongs in a child subtree (key_zeros < layer).
    fn insert_into_child(&self, key: &str, value: Cid) -> Result<MstNode, RepoError> {
        // Find the subtree that should contain this key.
        let mut new_entries = Vec::new();
        let mut inserted = false;

        for (i, entry) in self.entries.iter().enumerate() {
            if inserted {
                new_entries.push(entry.clone());
                continue;
            }
            match entry {
                NodeEntry::Leaf(leaf) => {
                    if key < leaf.key.as_str() && !inserted {
                        // Key should go before this leaf, in a new subtree
                        let child = MstNode::empty().add(key, value.clone())?;
                        new_entries.push(NodeEntry::Tree(child));
                        inserted = true;
                    }
                    new_entries.push(entry.clone());
                }
                NodeEntry::Tree(subtree) => {
                    // Determine if key belongs in this subtree.
                    // Key belongs here if it's less than the next leaf at this level.
                    let next_leaf_key = self.entries[i + 1..]
                        .iter()
                        .find_map(|e| e.as_leaf().map(|l| l.key.as_str()));
                    let belongs_here = match next_leaf_key {
                        Some(next) => key < next,
                        None => true,
                    };
                    if belongs_here {
                        let updated = subtree.add(key, value.clone())?;
                        new_entries.push(NodeEntry::Tree(updated));
                        inserted = true;
                    } else {
                        new_entries.push(entry.clone());
                    }
                }
            }
        }

        if !inserted {
            let child = MstNode::empty().add(key, value)?;
            new_entries.push(NodeEntry::Tree(child));
        }

        Ok(MstNode::from_entries(new_entries))
    }

    /// Create parent layers when key_zeros > current layer.
    fn create_parent_layers(
        &self,
        key: &str,
        value: Cid,
        key_zeros: usize,
    ) -> Result<MstNode, RepoError> {
        let (left, right) = self.split_around(key);

        let mut new_entries = Vec::new();
        if let Some(l) = left {
            if !l.entries.is_empty() {
                new_entries.push(NodeEntry::Tree(l));
            }
        }
        new_entries.push(NodeEntry::Leaf(Leaf {
            key: key.to_string(),
            value,
        }));
        if let Some(r) = right {
            if !r.entries.is_empty() {
                new_entries.push(NodeEntry::Tree(r));
            }
        }

        let mut node = MstNode::from_entries(new_entries);
        node.layer = Some(key_zeros);
        Ok(node)
    }

    // -----------------------------------------------------------------------
    // UPDATE
    // -----------------------------------------------------------------------

    /// Update an existing key's value. Returns error if key doesn't exist.
    pub fn update(&self, key: &str, value: Cid) -> Result<MstNode, RepoError> {
        ensure_valid_mst_key(key)?;
        let mut new_entries = Vec::new();
        let mut found = false;

        for entry in &self.entries {
            if found {
                new_entries.push(entry.clone());
                continue;
            }
            match entry {
                NodeEntry::Leaf(leaf) if leaf.key == key => {
                    new_entries.push(NodeEntry::Leaf(Leaf {
                        key: key.to_string(),
                        value: value.clone(),
                    }));
                    found = true;
                }
                NodeEntry::Tree(subtree) => {
                    if subtree.get(key).is_some() {
                        let updated = subtree.update(key, value.clone())?;
                        new_entries.push(NodeEntry::Tree(updated));
                        found = true;
                    } else {
                        new_entries.push(entry.clone());
                    }
                }
                _ => {
                    new_entries.push(entry.clone());
                }
            }
        }

        if !found {
            return Err(RepoError::KeyNotFound(key.to_string()));
        }
        Ok(MstNode::from_entries(new_entries))
    }

    // -----------------------------------------------------------------------
    // DELETE
    // -----------------------------------------------------------------------

    /// Delete a key. Returns error if key doesn't exist.
    pub fn delete(&self, key: &str) -> Result<MstNode, RepoError> {
        ensure_valid_mst_key(key)?;
        let result = self.delete_recurse(key)?;
        match result {
            Some(node) => Ok(node.trim_top()),
            None => Err(RepoError::KeyNotFound(key.to_string())),
        }
    }

    /// Recursively delete a key. Returns Some(new_node) if found, None if not found.
    fn delete_recurse(&self, key: &str) -> Result<Option<MstNode>, RepoError> {
        let mut new_entries = Vec::new();
        let mut found = false;

        let mut i = 0;
        while i < self.entries.len() {
            if found {
                new_entries.push(self.entries[i].clone());
                i += 1;
                continue;
            }

            match &self.entries[i] {
                NodeEntry::Leaf(leaf) if leaf.key == key => {
                    found = true;
                    // Check if we need to merge neighboring subtrees
                    let prev_tree = if !new_entries.is_empty() {
                        if let Some(NodeEntry::Tree(_)) = new_entries.last() {
                            if let NodeEntry::Tree(t) = new_entries.pop().unwrap() {
                                Some(t)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    let next_tree = if i + 1 < self.entries.len() && self.entries[i + 1].is_tree() {
                        i += 1; // consume the next tree entry
                        if let NodeEntry::Tree(t) = &self.entries[i] {
                            Some(t.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    match (prev_tree, next_tree) {
                        (Some(left), Some(right)) => {
                            let merged = left.append_merge(&right);
                            new_entries.push(NodeEntry::Tree(merged));
                        }
                        (Some(tree), None) => {
                            new_entries.push(NodeEntry::Tree(tree));
                        }
                        (None, Some(tree)) => {
                            new_entries.push(NodeEntry::Tree(tree));
                        }
                        (None, None) => {}
                    }
                    i += 1;
                }
                NodeEntry::Tree(subtree) => {
                    if let Some(updated) = subtree.delete_recurse(key)? {
                        found = true;
                        if !updated.entries.is_empty() {
                            new_entries.push(NodeEntry::Tree(updated));
                        }
                    } else {
                        new_entries.push(self.entries[i].clone());
                    }
                    i += 1;
                }
                _ => {
                    new_entries.push(self.entries[i].clone());
                    i += 1;
                }
            }
        }

        if found {
            Ok(Some(MstNode::from_entries(new_entries)))
        } else {
            Ok(None)
        }
    }

    // -----------------------------------------------------------------------
    // SPLIT / MERGE
    // -----------------------------------------------------------------------

    /// Split the tree around a key. Returns (entries < key, entries >= key).
    fn split_around(&self, key: &str) -> (Option<MstNode>, Option<MstNode>) {
        let mut left_entries = Vec::new();
        let mut right_entries = Vec::new();
        let mut past_key = false;

        for (i, entry) in self.entries.iter().enumerate() {
            if past_key {
                right_entries.push(entry.clone());
                continue;
            }
            match entry {
                NodeEntry::Leaf(leaf) => {
                    if leaf.key.as_str() >= key {
                        past_key = true;
                        right_entries.push(entry.clone());
                    } else {
                        left_entries.push(entry.clone());
                    }
                }
                NodeEntry::Tree(subtree) => {
                    // Determine if this tree needs splitting by looking at adjacent leaves
                    let prev_leaf_key = left_entries
                        .iter()
                        .rev()
                        .find_map(|e| e.as_leaf().map(|l| l.key.clone()));
                    let next_leaf_key = self.entries[i + 1..]
                        .iter()
                        .find_map(|e| e.as_leaf().map(|l| l.key.clone()));

                    let all_before = match &next_leaf_key {
                        Some(next) => next.as_str() <= key,
                        None => false,
                    };
                    let all_after = match &prev_leaf_key {
                        Some(prev) => prev.as_str() >= key,
                        None => left_entries.is_empty(),
                    };

                    if all_before {
                        left_entries.push(entry.clone());
                    } else if all_after && past_key {
                        right_entries.push(entry.clone());
                    } else {
                        // This tree straddles the split point — recurse
                        let (sub_left, sub_right) = subtree.split_around(key);
                        if let Some(sl) = sub_left {
                            if !sl.entries.is_empty() {
                                left_entries.push(NodeEntry::Tree(sl));
                            }
                        }
                        if let Some(sr) = sub_right {
                            if !sr.entries.is_empty() {
                                right_entries.push(NodeEntry::Tree(sr));
                            }
                        }
                        past_key = true;
                    }
                }
            }
        }

        let left = if left_entries.is_empty() {
            None
        } else {
            Some(MstNode::from_entries(left_entries))
        };
        let right = if right_entries.is_empty() {
            None
        } else {
            Some(MstNode::from_entries(right_entries))
        };
        (left, right)
    }

    /// Merge two trees (all keys in `other` must be > all keys in `self`).
    fn append_merge(&self, other: &MstNode) -> MstNode {
        let mut entries = self.entries.clone();
        entries.extend(other.entries.iter().cloned());
        MstNode::from_entries(entries)
    }

    /// If root only has a single tree child, trim to that child.
    fn trim_top(self) -> MstNode {
        if self.entries.len() == 1 {
            if let NodeEntry::Tree(subtree) = &self.entries[0] {
                return subtree.clone().trim_top();
            }
        }
        self
    }

    // -----------------------------------------------------------------------
    // TRAVERSAL
    // -----------------------------------------------------------------------

    /// Collect all leaves (key-value pairs) in order.
    pub fn leaves(&self) -> Vec<Leaf> {
        let mut result = Vec::new();
        self.collect_leaves(&mut result);
        result
    }

    fn collect_leaves(&self, result: &mut Vec<Leaf>) {
        for entry in &self.entries {
            match entry {
                NodeEntry::Leaf(leaf) => result.push(leaf.clone()),
                NodeEntry::Tree(subtree) => subtree.collect_leaves(result),
            }
        }
    }

    // -----------------------------------------------------------------------
    // SERIALIZATION
    // -----------------------------------------------------------------------

    /// Serialize this node and all children into a BlockMap.
    /// Returns the root CID and the blocks.
    pub fn get_all_blocks(&self) -> Result<(Cid, BlockMap), RepoError> {
        let mut blocks = BlockMap::new();
        let root_cid = self.collect_blocks(&mut blocks)?;
        Ok((root_cid, blocks))
    }

    fn collect_blocks(&self, blocks: &mut BlockMap) -> Result<Cid, RepoError> {
        // First collect all child blocks and get their CIDs
        let mut child_cids: Vec<Option<Cid>> = Vec::new();
        for entry in &self.entries {
            if let NodeEntry::Tree(subtree) = entry {
                let cid = subtree.collect_blocks(blocks)?;
                child_cids.push(Some(cid));
            } else {
                child_cids.push(None);
            }
        }

        // Serialize this node
        let data = self.to_node_data(&child_cids);
        let value = serialize_node_data(&data);
        let cid = blocks.add_value(&value)?;
        Ok(cid)
    }

    /// Convert to NodeData for serialization.
    /// `child_cids` is indexed by position in `self.entries` (one entry per entry).
    fn to_node_data(&self, child_cids: &[Option<Cid>]) -> NodeData {
        let mut left = None;
        let mut entries = Vec::new();
        let mut last_key = String::new();

        for (i, entry) in self.entries.iter().enumerate() {
            match entry {
                NodeEntry::Tree(_) => {
                    if entries.is_empty() && left.is_none() {
                        left = child_cids[i].clone();
                    } else if let Some(last_entry) = entries.last_mut() {
                        let e: &mut TreeEntry = last_entry;
                        e.tree = child_cids[i].clone();
                    }
                }
                NodeEntry::Leaf(leaf) => {
                    let prefix_len = count_prefix_len(&last_key, &leaf.key);
                    let key_suffix = leaf.key.as_bytes()[prefix_len..].to_vec();
                    entries.push(TreeEntry {
                        prefix_len,
                        key_suffix,
                        value: leaf.value.clone(),
                        tree: None,
                    });
                    last_key.clone_from(&leaf.key);
                }
            }
        }

        NodeData { left, entries }
    }

    /// Compute the CID for this node.
    pub fn get_pointer(&self) -> Result<Cid, RepoError> {
        if let Some(cid) = &self.pointer {
            return Ok(cid.clone());
        }
        // Need to serialize the whole tree to get accurate CIDs
        let (root_cid, _) = self.get_all_blocks()?;
        Ok(root_cid)
    }

    /// Get all CIDs referenced by this tree (node CIDs + value CIDs).
    pub fn all_cids(&self) -> Result<CidSet, RepoError> {
        let mut set = CidSet::new();
        let (_, blocks) = self.get_all_blocks()?;
        for cid in blocks.cids() {
            set.add(cid);
        }
        // Also add leaf value CIDs
        for leaf in self.leaves() {
            set.add(leaf.value);
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_blue_lex_data::LexValue;

    fn make_cid(data: &str) -> Cid {
        proto_blue_lex_cbor::cid_for_lex(&LexValue::String(data.into())).unwrap()
    }

    #[test]
    fn empty_tree() {
        let tree = MstNode::empty();
        assert!(tree.leaves().is_empty());
        assert!(tree.get("a/b").is_none());
    }

    #[test]
    fn add_and_get() {
        let tree = MstNode::empty();
        let cid = make_cid("val1");
        let tree = tree.add("app.bsky.feed.post/abc", cid.clone()).unwrap();
        assert_eq!(
            tree.get("app.bsky.feed.post/abc")
                .unwrap()
                .to_string_base32(),
            cid.to_string_base32()
        );
    }

    #[test]
    fn add_multiple_and_list() {
        let mut tree = MstNode::empty();
        let keys = vec![
            "app.bsky.feed.like/aaa",
            "app.bsky.feed.post/bbb",
            "app.bsky.feed.repost/ccc",
            "app.bsky.graph.follow/ddd",
        ];
        for key in &keys {
            let cid = make_cid(key);
            tree = tree.add(key, cid).unwrap();
        }

        let leaves = tree.leaves();
        assert_eq!(leaves.len(), 4);

        // Leaves should be sorted
        for i in 1..leaves.len() {
            assert!(leaves[i].key > leaves[i - 1].key);
        }
    }

    #[test]
    fn add_many_records() {
        let mut tree = MstNode::empty();
        for i in 0..100 {
            let key = format!("com.example.record/{i:04}");
            let cid = make_cid(&key);
            tree = tree.add(&key, cid).unwrap();
        }
        assert_eq!(tree.leaves().len(), 100);

        // Verify all are retrievable
        for i in 0..100 {
            let key = format!("com.example.record/{i:04}");
            assert!(tree.get(&key).is_some(), "Missing key: {key}");
        }
    }

    #[test]
    fn update_existing_key() {
        let tree = MstNode::empty();
        let cid1 = make_cid("val1");
        let cid2 = make_cid("val2");
        let tree = tree.add("a/b", cid1).unwrap();
        let tree = tree.update("a/b", cid2.clone()).unwrap();
        assert_eq!(
            tree.get("a/b").unwrap().to_string_base32(),
            cid2.to_string_base32()
        );
    }

    #[test]
    fn update_nonexistent_key_fails() {
        let tree = MstNode::empty();
        let cid = make_cid("val");
        assert!(tree.update("a/b", cid).is_err());
    }

    #[test]
    fn delete_key() {
        let mut tree = MstNode::empty();
        let keys = ["a/one", "b/two", "c/three"];
        for key in &keys {
            tree = tree.add(key, make_cid(key)).unwrap();
        }

        tree = tree.delete("b/two").unwrap();
        assert!(tree.get("b/two").is_none());
        assert!(tree.get("a/one").is_some());
        assert!(tree.get("c/three").is_some());
        assert_eq!(tree.leaves().len(), 2);
    }

    #[test]
    fn delete_nonexistent_key_fails() {
        let tree = MstNode::empty();
        assert!(tree.delete("a/b").is_err());
    }

    #[test]
    fn duplicate_add_fails() {
        let tree = MstNode::empty();
        let cid = make_cid("val");
        let tree = tree.add("a/b", cid.clone()).unwrap();
        assert!(tree.add("a/b", cid).is_err());
    }

    #[test]
    fn order_independence() {
        // Inserting keys in different orders should produce the same tree
        let keys: Vec<String> = (0..50)
            .map(|i| format!("com.example.record/{i:04}"))
            .collect();

        // Forward order
        let mut tree1 = MstNode::empty();
        for key in &keys {
            tree1 = tree1.add(key, make_cid(key)).unwrap();
        }

        // Reverse order
        let mut tree2 = MstNode::empty();
        for key in keys.iter().rev() {
            tree2 = tree2.add(key, make_cid(key)).unwrap();
        }

        // Both trees should have the same leaves
        let leaves1 = tree1.leaves();
        let leaves2 = tree2.leaves();
        assert_eq!(leaves1.len(), leaves2.len());
        for (l1, l2) in leaves1.iter().zip(leaves2.iter()) {
            assert_eq!(l1.key, l2.key);
            assert_eq!(l1.value.to_string_base32(), l2.value.to_string_base32());
        }

        // Both should produce the same root CID
        let (cid1, _) = tree1.get_all_blocks().unwrap();
        let (cid2, _) = tree2.get_all_blocks().unwrap();
        assert_eq!(cid1.to_string_base32(), cid2.to_string_base32());
    }

    #[test]
    fn serialization_roundtrip() {
        let mut tree = MstNode::empty();
        for i in 0..20 {
            let key = format!("com.example.record/{i:04}");
            tree = tree.add(&key, make_cid(&key)).unwrap();
        }

        // Serialize to blocks
        let (root_cid, blocks) = tree.get_all_blocks().unwrap();

        // Reload from blocks
        let loaded = MstNode::load(&root_cid, &blocks).unwrap();

        // Same leaves
        let orig_leaves = tree.leaves();
        let loaded_leaves = loaded.leaves();
        assert_eq!(orig_leaves.len(), loaded_leaves.len());
        for (o, l) in orig_leaves.iter().zip(loaded_leaves.iter()) {
            assert_eq!(o.key, l.key);
            assert_eq!(o.value.to_string_base32(), l.value.to_string_base32());
        }
    }

    #[test]
    fn add_delete_stress() {
        let mut tree = MstNode::empty();

        // Add 50 records
        for i in 0..50 {
            let key = format!("com.example/r{i:04}");
            tree = tree.add(&key, make_cid(&key)).unwrap();
        }
        assert_eq!(tree.leaves().len(), 50);

        // Delete every other record
        for i in (0..50).step_by(2) {
            let key = format!("com.example/r{i:04}");
            tree = tree.delete(&key).unwrap();
        }
        assert_eq!(tree.leaves().len(), 25);

        // Verify remaining
        for i in (1..50).step_by(2) {
            let key = format!("com.example/r{i:04}");
            assert!(tree.get(&key).is_some(), "Missing: {key}");
        }
    }

    #[test]
    fn add_delete_readd() {
        let mut tree = MstNode::empty();
        let cid = make_cid("val");
        tree = tree.add("a/b", cid.clone()).unwrap();
        tree = tree.delete("a/b").unwrap();
        assert!(tree.get("a/b").is_none());
        tree = tree.add("a/b", cid.clone()).unwrap();
        assert!(tree.get("a/b").is_some());
    }
}
