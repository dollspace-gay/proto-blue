//! A lazily loaded MST.
//!
//! [`Mst`] loads nodes on demand from a [`BlockSource`], so an operation only
//! touches the nodes on the paths it changes: each write costs O(depth), not
//! O(repo size). Node CIDs are cached once computed or loaded, and unchanged
//! subtrees are shared between versions.
//!
//! A source is synchronous. When it lacks a block, the operation fails with
//! [`RepoError::MissingBlock`] naming it; operations are pure, so the caller
//! can fetch that block (for example from an async database), add it to its
//! source, and run the operation again.
//!
//! The algorithms follow the atproto reference implementation's MST (add,
//! update, delete, split, merge and trim), so trees are canonical and match
//! [`super::MstNode`] byte for byte.
//!
//! [`Mst::diff`] reports the nodes a change adds and the nodes it leaves
//! unreferenced, net across a batch, walking only changed paths.
//! [`Mst::covering_proof`] returns the blocks a consumer needs to check a key
//! and to invert an operation on it (as firehose `#commit` events require).

use std::sync::{Arc, OnceLock};

use proto_blue_lex_data::Cid;

use crate::block_map::BlockMap;
use crate::cid_set::CidSet;
use crate::error::RepoError;
use crate::mst::util::{
    NodeData, TreeEntry, count_prefix_len, deserialize_node_data, ensure_valid_mst_key,
    leading_zeros_on_hash, serialize_node_data,
};

/// Where an [`Mst`] reads node blocks from.
pub trait BlockSource {
    /// The bytes of the block `cid`, if this source has it.
    fn get_block(&self, cid: &Cid) -> Option<&[u8]>;
}

impl BlockSource for BlockMap {
    fn get_block(&self, cid: &Cid) -> Option<&[u8]> {
        self.get(cid)
    }
}

/// A source with no blocks, for trees that are entirely in memory.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoBlocks;

impl BlockSource for NoBlocks {
    fn get_block(&self, _cid: &Cid) -> Option<&[u8]> {
        None
    }
}

/// One operation in a batch.
#[derive(Debug, Clone)]
pub enum MstOp {
    Add { key: String, value: Cid },
    Update { key: String, value: Cid },
    Delete { key: String },
}

impl MstOp {
    #[must_use]
    pub fn key(&self) -> &str {
        match self {
            Self::Add { key, .. } | Self::Update { key, .. } | Self::Delete { key } => key,
        }
    }
}

/// The node-level effect of a change, net across a batch.
#[derive(Debug, Default)]
pub struct MstDiff {
    /// Blocks of the MST nodes that are in the new tree and weren't in the old one.
    pub added: BlockMap,
    /// CIDs of the MST nodes that were in the old tree and aren't in the new one.
    pub removed: CidSet,
}

#[derive(Debug, Clone)]
enum NodeRef {
    /// Not loaded yet. `layer` is known when the parent's layer is.
    Stored {
        cid: Cid,
        layer: Option<usize>,
    },
    Loaded(Arc<Node>),
}

#[derive(Debug)]
struct Node {
    entries: Vec<Entry>,
    layer: usize,
    /// Decoded from a source (so it was in the tree that source holds).
    from_storage: bool,
    cid: OnceLock<Cid>,
}

#[derive(Debug, Clone)]
enum Entry {
    Leaf { key: String, value: Cid },
    Tree(NodeRef),
}

impl Entry {
    fn leaf_key(&self) -> Option<&str> {
        match self {
            Self::Leaf { key, .. } => Some(key),
            Self::Tree(_) => None,
        }
    }

    fn as_tree(&self) -> Option<&NodeRef> {
        match self {
            Self::Tree(t) => Some(t),
            Self::Leaf { .. } => None,
        }
    }
}

/// A Merkle Search Tree whose nodes load on demand.
#[derive(Debug, Clone)]
pub struct Mst {
    root: NodeRef,
}

fn new_node(layer: usize, entries: Vec<Entry>) -> NodeRef {
    NodeRef::Loaded(Arc::new(Node {
        entries,
        layer,
        from_storage: false,
        cid: OnceLock::new(),
    }))
}

impl Mst {
    /// An empty tree.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            root: new_node(0, Vec::new()),
        }
    }

    /// The stored tree rooted at `root`. Nothing is loaded until used.
    #[must_use]
    pub fn load(root: Cid) -> Self {
        Self {
            root: NodeRef::Stored {
                cid: root,
                layer: None,
            },
        }
    }

    /// The root node's CID (computes the CIDs of changed nodes).
    pub fn root_cid(&self) -> Result<Cid, RepoError> {
        node_cid(&self.root)
    }

    /// The value stored at `key`, if any.
    pub fn get(&self, key: &str, src: &dyn BlockSource) -> Result<Option<Cid>, RepoError> {
        get(&self.root, key, src)
    }

    /// Adds `key`. Fails with [`RepoError::KeyAlreadyExists`] if present.
    pub fn add(&self, key: &str, value: Cid, src: &dyn BlockSource) -> Result<Self, RepoError> {
        ensure_valid_mst_key(key)?;
        let zeros = leading_zeros_on_hash(key);
        Ok(Self {
            root: add(&self.root, key, value, zeros, src)?,
        })
    }

    /// Replaces the value at `key`. Fails with [`RepoError::KeyNotFound`] if absent.
    pub fn update(&self, key: &str, value: Cid, src: &dyn BlockSource) -> Result<Self, RepoError> {
        ensure_valid_mst_key(key)?;
        Ok(Self {
            root: update(&self.root, key, value, src)?,
        })
    }

    /// Removes `key`. Fails with [`RepoError::KeyNotFound`] if absent.
    pub fn delete(&self, key: &str, src: &dyn BlockSource) -> Result<Self, RepoError> {
        ensure_valid_mst_key(key)?;
        let altered = delete_recurse(&self.root, key, src)?;
        Ok(Self {
            root: trim_top(altered, src)?,
        })
    }

    /// Applies `ops` in order.
    pub fn apply(&self, ops: &[MstOp], src: &dyn BlockSource) -> Result<Self, RepoError> {
        let mut tree = self.clone();
        for op in ops {
            tree = match op {
                MstOp::Add { key, value } => tree.add(key, value.clone(), src)?,
                MstOp::Update { key, value } => tree.update(key, value.clone(), src)?,
                MstOp::Delete { key } => tree.delete(key, src)?,
            };
        }
        Ok(tree)
    }

    /// Every leaf, in key order. Loads the whole tree; for exports and checks.
    pub fn leaves(&self, src: &dyn BlockSource) -> Result<Vec<(String, Cid)>, RepoError> {
        let mut out = Vec::new();
        collect_leaves(&self.root, src, &mut out)?;
        Ok(out)
    }

    /// The node-level difference from `old` to `new`, net: nodes `new` has
    /// that `old` doesn't (with their blocks), and nodes `old` has that `new`
    /// doesn't. Walks only the paths that differ. `src` must hold the nodes
    /// of `old` that a walk reaches (they are read to find what was removed).
    pub fn diff(old: &Self, new: &Self, src: &dyn BlockSource) -> Result<MstDiff, RepoError> {
        // Nodes the new tree holds in memory, and the unchanged subtrees it points at.
        let mut in_new = CidSet::new();
        new_frontier(&new.root, &mut in_new)?;

        // Walk the old tree, stopping wherever it meets something still present.
        let mut removed = CidSet::new();
        let mut still_present = CidSet::new();
        let mut stack = vec![old.root.clone()];
        while let Some(nref) = stack.pop() {
            let cid = node_cid(&nref)?;
            if in_new.has(&cid) {
                still_present.add(cid);
                continue;
            }
            if removed.has(&cid) {
                continue;
            }
            removed.add(cid);
            let node = load(&nref, src)?;
            for e in &node.entries {
                if let Entry::Tree(t) = e {
                    stack.push(t.clone());
                }
            }
        }

        // Walk the new tree, stopping at anything the old tree had.
        let mut added = BlockMap::new();
        let mut stack = vec![new.root.clone()];
        while let Some(nref) = stack.pop() {
            let NodeRef::Loaded(node) = &nref else {
                continue;
            };
            let cid = node_cid(&nref)?;
            if node.from_storage || still_present.has(&cid) || added.has(&cid) {
                continue;
            }
            let bytes = node_bytes(node)?;
            added.set(cid, bytes);
            for e in &node.entries {
                if let Entry::Tree(t) = e {
                    stack.push(t.clone());
                }
            }
        }
        Ok(MstDiff { added, removed })
    }

    /// The node blocks that prove `key`'s presence or absence in this tree
    /// and let a consumer invert an operation on it: the search path to
    /// `key` and, where `key` is present, the inner edges of the subtrees on
    /// either side of it (a delete merges those).
    pub fn covering_proof(&self, key: &str, src: &dyn BlockSource) -> Result<BlockMap, RepoError> {
        let mut out = BlockMap::new();
        covering(&self.root, key, src, &mut out)?;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Loading and serialisation
// ---------------------------------------------------------------------------

fn load(nref: &NodeRef, src: &dyn BlockSource) -> Result<Arc<Node>, RepoError> {
    match nref {
        NodeRef::Loaded(n) => Ok(Arc::clone(n)),
        NodeRef::Stored { cid, layer } => {
            let bytes = src
                .get_block(cid)
                .ok_or_else(|| RepoError::MissingBlock(cid.clone()))?;
            decode_node(cid, bytes, *layer, src)
        }
    }
}

fn decode_node(
    cid: &Cid,
    bytes: &[u8],
    layer: Option<usize>,
    src: &dyn BlockSource,
) -> Result<Arc<Node>, RepoError> {
    let value = proto_blue_lex_cbor::decode(bytes)?;
    let data = deserialize_node_data(&value)?;
    let invalid = |why: &str| RepoError::InvalidMst(format!("node {cid}: {why}"));

    let mut keys = Vec::with_capacity(data.entries.len());
    let mut last = String::new();
    for e in &data.entries {
        if e.prefix_len > last.len() {
            return Err(invalid("prefix longer than the previous key"));
        }
        let suffix = std::str::from_utf8(&e.key_suffix).map_err(|_| invalid("key is not UTF-8"))?;
        let mut key = String::with_capacity(e.prefix_len + suffix.len());
        key.push_str(
            last.get(..e.prefix_len)
                .ok_or_else(|| invalid("prefix splits a character"))?,
        );
        key.push_str(suffix);
        ensure_valid_mst_key(&key)?;
        if !keys.is_empty() && key <= last {
            return Err(invalid("keys out of order"));
        }
        last.clone_from(&key);
        keys.push(key);
    }

    let layer = match (layer, keys.first()) {
        (Some(l), _) => l,
        (None, Some(k)) => leading_zeros_on_hash(k),
        (None, None) => match &data.left {
            Some(left) => {
                let child = load(
                    &NodeRef::Stored {
                        cid: left.clone(),
                        layer: None,
                    },
                    src,
                )?;
                child.layer + 1
            }
            None => 0,
        },
    };
    for k in &keys {
        if leading_zeros_on_hash(k) != layer {
            return Err(invalid("a key is on the wrong layer"));
        }
    }
    let child_layer = |what: &str| {
        layer
            .checked_sub(1)
            .ok_or_else(|| invalid(&format!("{what} below layer 0")))
    };

    let mut entries = Vec::with_capacity(keys.len() * 2 + 1);
    if let Some(left) = &data.left {
        entries.push(Entry::Tree(NodeRef::Stored {
            cid: left.clone(),
            layer: Some(child_layer("subtree")?),
        }));
    }
    for (key, e) in keys.into_iter().zip(&data.entries) {
        entries.push(Entry::Leaf {
            key,
            value: e.value.clone(),
        });
        if let Some(t) = &e.tree {
            entries.push(Entry::Tree(NodeRef::Stored {
                cid: t.clone(),
                layer: Some(child_layer("subtree")?),
            }));
        }
    }
    let node = Node {
        entries,
        layer,
        from_storage: true,
        cid: OnceLock::new(),
    };
    let _ = node.cid.set(cid.clone());
    Ok(Arc::new(node))
}

fn node_data(node: &Node) -> Result<NodeData, RepoError> {
    let mut left = None;
    let mut entries: Vec<TreeEntry> = Vec::new();
    let mut last_key = "";
    let mut prev_was_tree = false;
    for e in &node.entries {
        match e {
            Entry::Tree(t) => {
                if prev_was_tree {
                    return Err(RepoError::InvalidMst("two adjacent subtrees".into()));
                }
                let cid = node_cid(t)?;
                match entries.last_mut() {
                    Some(last) => last.tree = Some(cid),
                    None => left = Some(cid),
                }
                prev_was_tree = true;
            }
            Entry::Leaf { key, value } => {
                let prefix_len = count_prefix_len(last_key, key);
                entries.push(TreeEntry {
                    prefix_len,
                    key_suffix: key.as_bytes()[prefix_len..].to_vec(),
                    value: value.clone(),
                    tree: None,
                });
                last_key = key;
                prev_was_tree = false;
            }
        }
    }
    Ok(NodeData { left, entries })
}

fn node_bytes(node: &Node) -> Result<Vec<u8>, RepoError> {
    Ok(proto_blue_lex_cbor::encode(&serialize_node_data(
        &node_data(node)?,
    ))?)
}

fn node_cid(nref: &NodeRef) -> Result<Cid, RepoError> {
    match nref {
        NodeRef::Stored { cid, .. } => Ok(cid.clone()),
        NodeRef::Loaded(node) => {
            if let Some(cid) = node.cid.get() {
                return Ok(cid.clone());
            }
            let cid = proto_blue_lex_cbor::cid_for_lex(&serialize_node_data(&node_data(node)?))?;
            Ok(node.cid.get_or_init(|| cid).clone())
        }
    }
}

fn layer_of(nref: &NodeRef, src: &dyn BlockSource) -> Result<usize, RepoError> {
    match nref {
        NodeRef::Stored { layer: Some(l), .. } => Ok(*l),
        _ => Ok(load(nref, src)?.layer),
    }
}

/// Unchanged-subtree pointers and in-memory node CIDs of a tree.
fn new_frontier(nref: &NodeRef, out: &mut CidSet) -> Result<(), RepoError> {
    let mut stack = vec![nref.clone()];
    while let Some(n) = stack.pop() {
        out.add(node_cid(&n)?);
        if let NodeRef::Loaded(node) = &n {
            for e in &node.entries {
                if let Entry::Tree(t) = e {
                    stack.push(t.clone());
                }
            }
        }
    }
    Ok(())
}

fn collect_leaves(
    nref: &NodeRef,
    src: &dyn BlockSource,
    out: &mut Vec<(String, Cid)>,
) -> Result<(), RepoError> {
    let node = load(nref, src)?;
    for e in &node.entries {
        match e {
            Entry::Leaf { key, value } => out.push((key.clone(), value.clone())),
            Entry::Tree(t) => collect_leaves(t, src, out)?,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Operations (the reference MST's algorithms)
// ---------------------------------------------------------------------------

/// Index of the first leaf with key >= `key`, or the entry count.
fn gte_leaf_index(entries: &[Entry], key: &str) -> usize {
    entries
        .iter()
        .position(|e| e.leaf_key().is_some_and(|k| k >= key))
        .unwrap_or(entries.len())
}

fn with_entries(node: &Node, entries: Vec<Entry>) -> NodeRef {
    new_node(node.layer, entries)
}

fn get(nref: &NodeRef, key: &str, src: &dyn BlockSource) -> Result<Option<Cid>, RepoError> {
    let node = load(nref, src)?;
    let index = gte_leaf_index(&node.entries, key);
    if let Some(Entry::Leaf { key: k, value }) = node.entries.get(index)
        && k == key
    {
        return Ok(Some(value.clone()));
    }
    match index.checked_sub(1).and_then(|i| node.entries[i].as_tree()) {
        Some(prev) => get(prev, key, src),
        None => Ok(None),
    }
}

fn add(
    nref: &NodeRef,
    key: &str,
    value: Cid,
    zeros: usize,
    src: &dyn BlockSource,
) -> Result<NodeRef, RepoError> {
    let node = load(nref, src)?;
    let layer = node.layer;
    let leaf = Entry::Leaf {
        key: key.to_owned(),
        value,
    };
    match zeros.cmp(&layer) {
        std::cmp::Ordering::Equal => {
            let index = gte_leaf_index(&node.entries, key);
            if let Some(Entry::Leaf { key: k, .. }) = node.entries.get(index)
                && k == key
            {
                return Err(RepoError::KeyAlreadyExists(key.to_owned()));
            }
            let prev = index.checked_sub(1).and_then(|i| node.entries[i].as_tree());
            let mut entries = Vec::with_capacity(node.entries.len() + 2);
            match prev {
                None => {
                    entries.extend_from_slice(&node.entries[..index]);
                    entries.push(leaf);
                    entries.extend_from_slice(&node.entries[index..]);
                }
                Some(prev) => {
                    let (left, right) = split_around(prev, key, src)?;
                    entries.extend_from_slice(&node.entries[..index - 1]);
                    if let Some(l) = left {
                        entries.push(Entry::Tree(l));
                    }
                    entries.push(leaf);
                    if let Some(r) = right {
                        entries.push(Entry::Tree(r));
                    }
                    entries.extend_from_slice(&node.entries[index..]);
                }
            }
            Ok(with_entries(&node, entries))
        }
        std::cmp::Ordering::Less => {
            let index = gte_leaf_index(&node.entries, key);
            let prev = index.checked_sub(1).and_then(|i| node.entries[i].as_tree());
            let Entry::Leaf { value, .. } = leaf else {
                unreachable!()
            };
            let mut entries = node.entries.clone();
            match prev {
                Some(prev) => {
                    let updated = add(prev, key, value, zeros, src)?;
                    entries[index - 1] = Entry::Tree(updated);
                }
                None => {
                    let child = new_node(layer - 1, Vec::new());
                    let updated = add(&child, key, value, zeros, src)?;
                    entries.insert(index, Entry::Tree(updated));
                }
            }
            Ok(with_entries(&node, entries))
        }
        std::cmp::Ordering::Greater => {
            let (mut left, mut right) = split_around(nref, key, src)?;
            for _ in 1..(zeros - layer) {
                if let Some(l) = left.take() {
                    let l_layer = layer_of(&l, src)?;
                    left = Some(new_node(l_layer + 1, vec![Entry::Tree(l)]));
                }
                if let Some(r) = right.take() {
                    let r_layer = layer_of(&r, src)?;
                    right = Some(new_node(r_layer + 1, vec![Entry::Tree(r)]));
                }
            }
            let mut entries = Vec::with_capacity(3);
            if let Some(l) = left {
                entries.push(Entry::Tree(l));
            }
            entries.push(leaf);
            if let Some(r) = right {
                entries.push(Entry::Tree(r));
            }
            Ok(new_node(zeros, entries))
        }
    }
}

fn update(
    nref: &NodeRef,
    key: &str,
    value: Cid,
    src: &dyn BlockSource,
) -> Result<NodeRef, RepoError> {
    let node = load(nref, src)?;
    let index = gte_leaf_index(&node.entries, key);
    if let Some(Entry::Leaf { key: k, .. }) = node.entries.get(index)
        && k == key
    {
        let mut entries = node.entries.clone();
        entries[index] = Entry::Leaf {
            key: key.to_owned(),
            value,
        };
        return Ok(with_entries(&node, entries));
    }
    if let Some(prev) = index.checked_sub(1).and_then(|i| node.entries[i].as_tree()) {
        let updated = update(prev, key, value, src)?;
        let mut entries = node.entries.clone();
        entries[index - 1] = Entry::Tree(updated);
        return Ok(with_entries(&node, entries));
    }
    Err(RepoError::KeyNotFound(key.to_owned()))
}

fn delete_recurse(nref: &NodeRef, key: &str, src: &dyn BlockSource) -> Result<NodeRef, RepoError> {
    let node = load(nref, src)?;
    let index = gte_leaf_index(&node.entries, key);
    if let Some(Entry::Leaf { key: k, .. }) = node.entries.get(index)
        && k == key
    {
        let prev = index.checked_sub(1).and_then(|i| node.entries[i].as_tree());
        let next = node.entries.get(index + 1).and_then(Entry::as_tree);
        let mut entries = Vec::with_capacity(node.entries.len());
        if let (Some(prev), Some(next)) = (prev, next) {
            let merged = append_merge(prev, next, src)?;
            entries.extend_from_slice(&node.entries[..index - 1]);
            entries.push(Entry::Tree(merged));
            entries.extend_from_slice(&node.entries[index + 2..]);
        } else {
            entries.extend_from_slice(&node.entries[..index]);
            entries.extend_from_slice(&node.entries[index + 1..]);
        }
        return Ok(with_entries(&node, entries));
    }
    if let Some(prev) = index.checked_sub(1).and_then(|i| node.entries[i].as_tree()) {
        let subtree = delete_recurse(prev, key, src)?;
        let mut entries = node.entries.clone();
        if load(&subtree, src)?.entries.is_empty() {
            entries.remove(index - 1);
        } else {
            entries[index - 1] = Entry::Tree(subtree);
        }
        return Ok(with_entries(&node, entries));
    }
    Err(RepoError::KeyNotFound(key.to_owned()))
}

fn append_merge(
    left: &NodeRef,
    right: &NodeRef,
    src: &dyn BlockSource,
) -> Result<NodeRef, RepoError> {
    let l = load(left, src)?;
    let r = load(right, src)?;
    if l.layer != r.layer {
        return Err(RepoError::InvalidMst(
            "can't merge subtrees on different layers".into(),
        ));
    }
    let mut entries = Vec::with_capacity(l.entries.len() + r.entries.len());
    if let (Some(Entry::Tree(last)), Some(Entry::Tree(first))) =
        (l.entries.last(), r.entries.first())
    {
        let merged = append_merge(last, first, src)?;
        entries.extend_from_slice(&l.entries[..l.entries.len() - 1]);
        entries.push(Entry::Tree(merged));
        entries.extend_from_slice(&r.entries[1..]);
    } else {
        entries.extend_from_slice(&l.entries);
        entries.extend_from_slice(&r.entries);
    }
    Ok(with_entries(&l, entries))
}

/// Splits into (keys < `key`, keys >= `key`); an empty side is `None`.
fn split_around(
    nref: &NodeRef,
    key: &str,
    src: &dyn BlockSource,
) -> Result<(Option<NodeRef>, Option<NodeRef>), RepoError> {
    let node = load(nref, src)?;
    let index = gte_leaf_index(&node.entries, key);
    let mut left: Vec<Entry> = node.entries[..index].to_vec();
    let mut right: Vec<Entry> = node.entries[index..].to_vec();
    if let Some(Entry::Tree(last)) = left.last().cloned() {
        left.pop();
        let (sl, sr) = split_around(&last, key, src)?;
        if let Some(sl) = sl {
            left.push(Entry::Tree(sl));
        }
        if let Some(sr) = sr {
            right.insert(0, Entry::Tree(sr));
        }
    }
    let side = |entries: Vec<Entry>| (!entries.is_empty()).then(|| with_entries(&node, entries));
    Ok((side(left), side(right)))
}

fn trim_top(nref: NodeRef, src: &dyn BlockSource) -> Result<NodeRef, RepoError> {
    let node = load(&nref, src)?;
    // An empty tree is layer 0, as the reference has it: keeping the
    // deleted key's layer would put later, lower keys under a phantom
    // level (the bytes are the same; the next adds aren't).
    if node.entries.is_empty() {
        return Ok(new_node(0, Vec::new()));
    }
    if node.entries.len() == 1
        && let Entry::Tree(only) = &node.entries[0]
    {
        return trim_top(only.clone(), src);
    }
    Ok(nref)
}

// ---------------------------------------------------------------------------
// Covering proofs
// ---------------------------------------------------------------------------

fn add_block(node: &Node, nref: &NodeRef, out: &mut BlockMap) -> Result<(), RepoError> {
    let cid = node_cid(nref)?;
    if !out.has(&cid) {
        out.set(cid, node_bytes(node)?);
    }
    Ok(())
}

fn covering(
    nref: &NodeRef,
    key: &str,
    src: &dyn BlockSource,
    out: &mut BlockMap,
) -> Result<(), RepoError> {
    let node = load(nref, src)?;
    add_block(&node, nref, out)?;
    let index = gte_leaf_index(&node.entries, key);
    if let Some(Entry::Leaf { key: k, .. }) = node.entries.get(index)
        && k == key
    {
        // Deleting this key merges the subtrees on either side of it along
        // their inner edges, so include those edges.
        if let Some(prev) = index.checked_sub(1).and_then(|i| node.entries[i].as_tree()) {
            edge(prev, src, out, true)?;
        }
        if let Some(next) = node.entries.get(index + 1).and_then(Entry::as_tree) {
            edge(next, src, out, false)?;
        }
        return Ok(());
    }
    if let Some(prev) = index.checked_sub(1).and_then(|i| node.entries[i].as_tree()) {
        covering(prev, key, src, out)?;
    }
    Ok(())
}

/// The rightmost (`right = true`) or leftmost spine of a subtree.
fn edge(
    nref: &NodeRef,
    src: &dyn BlockSource,
    out: &mut BlockMap,
    right: bool,
) -> Result<(), RepoError> {
    let node = load(nref, src)?;
    add_block(&node, nref, out)?;
    let next = if right {
        node.entries.last()
    } else {
        node.entries.first()
    };
    if let Some(Entry::Tree(t)) = next {
        edge(t, src, out, right)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mst::MstNode;
    use proto_blue_lex_data::LexValue;
    use std::collections::{BTreeMap, BTreeSet};

    fn cid_of(s: &str) -> Cid {
        proto_blue_lex_cbor::cid_for_lex(&LexValue::String(s.into())).unwrap()
    }

    /// A small deterministic PRNG, so failures reproduce.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    fn key(i: u64) -> String {
        format!("app.bsky.feed.post/3m{i:011}")
    }

    /// The eager tree of exactly these records: root CID and all node blocks.
    fn eager(records: &BTreeMap<String, Cid>) -> (Cid, BlockMap) {
        let mut t = MstNode::empty();
        for (k, v) in records {
            t = t.add(k, v.clone()).unwrap();
        }
        t.get_all_blocks().unwrap()
    }

    /// Runs `f` against `store` as a lazily fetching caller would: on a
    /// missing block, copy it from `full` into `store` and retry.
    fn with_fetch<T>(
        store: &mut BlockMap,
        full: &BlockMap,
        mut f: impl FnMut(&BlockMap) -> Result<T, RepoError>,
    ) -> (T, usize) {
        let mut fetched = 0;
        loop {
            match f(store) {
                Ok(v) => return (v, fetched),
                Err(RepoError::MissingBlock(cid)) => {
                    let bytes = full
                        .get(&cid)
                        .expect("block exists in the full store")
                        .to_vec();
                    store.set(cid, bytes);
                    fetched += 1;
                }
                Err(e) => panic!("{e}"),
            }
        }
    }

    #[test]
    fn empty_tree_matches_eager() {
        let (cid, _) = MstNode::empty().get_all_blocks().unwrap();
        assert_eq!(Mst::empty().root_cid().unwrap(), cid);
    }

    /// Emptying a tree whose keys sit above layer 0, then adding lower
    /// keys, gives the canonical tree (the empty tree is layer 0).
    #[test]
    fn a_tree_emptied_from_a_high_layer_grows_back_canonically() {
        let high: Vec<String> = (0..4000)
            .map(key)
            .filter(|k| leading_zeros_on_hash(k) >= 1)
            .take(3)
            .collect();
        let low: Vec<String> = (0..4000)
            .map(key)
            .filter(|k| leading_zeros_on_hash(k) == 0)
            .take(5)
            .collect();
        for n in 1..=high.len() {
            let mut t = Mst::empty();
            for k in &high[..n] {
                t = t.add(k, cid_of(k), &NoBlocks).unwrap();
            }
            for k in &high[..n] {
                t = t.delete(k, &NoBlocks).unwrap();
            }
            assert_eq!(t.root_cid().unwrap(), Mst::empty().root_cid().unwrap());
            let mut records = BTreeMap::new();
            for k in &low {
                t = t.add(k, cid_of(k), &NoBlocks).unwrap();
                records.insert(k.clone(), cid_of(k));
                assert_eq!(
                    t.root_cid().unwrap(),
                    eager(&records).0,
                    "{n} high keys, then {k}"
                );
            }
        }
    }

    #[test]
    fn random_batches_match_the_eager_tree_and_diffs_are_exact() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut records: BTreeMap<String, Cid> = BTreeMap::new();
        for i in 0..400 {
            records.insert(key(i * 7_919 % 100_003), cid_of(&format!("v{i}")));
        }
        let (mut root, mut full) = eager(&records);

        for round in 0..60 {
            // A batch of up to 12 random ops against the stored tree.
            let mut ops = Vec::new();
            let mut next = records.clone();
            for _ in 0..(1 + rng.below(12)) {
                let roll = rng.below(3);
                if roll == 0 || next.is_empty() {
                    let k = key(rng.next() % 100_003);
                    if next.contains_key(&k) {
                        continue;
                    }
                    let v = cid_of(&format!("r{round}-{k}"));
                    next.insert(k.clone(), v.clone());
                    ops.push(MstOp::Add { key: k, value: v });
                } else {
                    let keys: Vec<String> = next.keys().cloned().collect();
                    let k = keys[rng.below(keys.len())].clone();
                    if roll == 1 {
                        let v = cid_of(&format!("u{round}-{k}"));
                        next.insert(k.clone(), v.clone());
                        ops.push(MstOp::Update { key: k, value: v });
                    } else {
                        next.remove(&k);
                        ops.push(MstOp::Delete { key: k });
                    }
                }
            }

            let old = Mst::load(root.clone());
            let mut store = BlockMap::new();
            let (new_tree, fetched) = with_fetch(&mut store, &full, |s| old.apply(&ops, s));
            let (new_root, new_full) = eager(&next);
            assert_eq!(
                new_tree.root_cid().unwrap(),
                new_root,
                "round {round}: root differs from eager"
            );

            // Only a few paths' worth of nodes were read, not the whole tree.
            assert!(
                fetched <= ops.len() * 20 + 10,
                "round {round}: fetched {fetched} of {} nodes",
                full.len()
            );

            let (diff, _) = with_fetch(&mut store, &full, |s| Mst::diff(&old, &new_tree, s));
            let old_set: BTreeSet<Cid> = full.cids().into_iter().collect();
            let new_set: BTreeSet<Cid> = new_full.cids().into_iter().collect();
            let added: BTreeSet<Cid> = diff.added.cids().into_iter().collect();
            let removed: BTreeSet<Cid> = diff.removed.iter().cloned().collect();
            assert_eq!(added, &new_set - &old_set, "round {round}: added");
            assert_eq!(removed, &old_set - &new_set, "round {round}: removed");
            for (cid, bytes) in diff.added.iter() {
                assert_eq!(
                    Some(bytes),
                    new_full.get(cid),
                    "round {round}: added block bytes"
                );
            }

            records = next;
            root = new_root;
            full = new_full;
        }
    }

    #[test]
    fn duplicate_add_and_missing_key_fail() {
        let t = Mst::empty().add("a/b", cid_of("1"), &NoBlocks).unwrap();
        assert!(matches!(
            t.add("a/b", cid_of("2"), &NoBlocks),
            Err(RepoError::KeyAlreadyExists(_))
        ));
        assert!(matches!(
            t.update("a/c", cid_of("2"), &NoBlocks),
            Err(RepoError::KeyNotFound(_))
        ));
        assert!(matches!(
            t.delete("a/c", &NoBlocks),
            Err(RepoError::KeyNotFound(_))
        ));
    }

    #[test]
    fn get_reads_only_one_path() {
        let mut records = BTreeMap::new();
        for i in 0..2_000 {
            records.insert(key(i), cid_of(&format!("v{i}")));
        }
        let (root, full) = eager(&records);
        let tree = Mst::load(root);
        let mut store = BlockMap::new();
        let (got, fetched) = with_fetch(&mut store, &full, |s| tree.get(&key(1234), s));
        assert_eq!(got, Some(cid_of("v1234")));
        assert!(fetched <= 8, "fetched {fetched} of {}", full.len());
        let (none, _) = with_fetch(&mut store, &full, |s| tree.get(&key(99_999), s));
        assert_eq!(none, None);
    }

    /// Covering proofs let a consumer invert every op of a batch using only
    /// the proof blocks, and recover the previous root.
    #[test]
    fn covering_proofs_are_enough_to_invert_a_batch() {
        let mut rng = Rng(42);
        let mut records: BTreeMap<String, Cid> = BTreeMap::new();
        for i in 0..300 {
            records.insert(key(i * 31 % 50_021), cid_of(&format!("v{i}")));
        }
        let (mut root, mut full) = eager(&records);
        for round in 0..40 {
            let mut ops = Vec::new();
            let mut inverse = Vec::new();
            let mut next = records.clone();
            for _ in 0..(1 + rng.below(6)) {
                let keys: Vec<String> = next.keys().cloned().collect();
                match rng.below(3) {
                    0 => {
                        let k = key(rng.next() % 50_021);
                        if next.contains_key(&k) {
                            continue;
                        }
                        let v = cid_of(&format!("a{round}{k}"));
                        next.insert(k.clone(), v.clone());
                        ops.push(MstOp::Add {
                            key: k.clone(),
                            value: v,
                        });
                        inverse.push(MstOp::Delete { key: k });
                    }
                    1 => {
                        let k = keys[rng.below(keys.len())].clone();
                        let old_v = next[&k].clone();
                        let v = cid_of(&format!("u{round}{k}"));
                        next.insert(k.clone(), v.clone());
                        ops.push(MstOp::Update {
                            key: k.clone(),
                            value: v,
                        });
                        inverse.push(MstOp::Update {
                            key: k,
                            value: old_v,
                        });
                    }
                    _ => {
                        let k = keys[rng.below(keys.len())].clone();
                        let old_v = next.remove(&k).unwrap();
                        ops.push(MstOp::Delete { key: k.clone() });
                        inverse.push(MstOp::Add {
                            key: k,
                            value: old_v,
                        });
                    }
                }
            }
            let (new_root, new_full) = eager(&next);
            let new_tree = Mst::load(new_root.clone());

            let mut proof = BlockMap::new();
            for op in &ops {
                let mut store = BlockMap::new();
                let (p, _) = with_fetch(&mut store, &new_full, |s| {
                    new_tree.covering_proof(op.key(), s)
                });
                proof.add_map(&p);
            }
            inverse.reverse();
            // No fallback source: every block must be in the proof.
            let inverted = new_tree
                .apply(&inverse, &proof)
                .unwrap_or_else(|e| panic!("round {round}: proof was not enough: {e}"));
            assert_eq!(
                inverted.root_cid().unwrap(),
                root,
                "round {round}: inversion"
            );

            records = next;
            root = new_root;
            full = new_full;
        }
        let _ = full;
    }

    #[test]
    fn malformed_nodes_are_rejected() {
        // A node claiming a key on the wrong layer.
        let k = (0..)
            .map(|i| format!("a/{i}"))
            .find(|k| leading_zeros_on_hash(k) == 0)
            .unwrap();
        let data = NodeData {
            left: None,
            entries: vec![TreeEntry {
                prefix_len: 0,
                key_suffix: k.into_bytes(),
                value: cid_of("x"),
                tree: None,
            }],
        };
        let mut blocks = BlockMap::new();
        let cid = blocks.add_value(&serialize_node_data(&data)).unwrap();
        let bad = Mst {
            root: NodeRef::Stored {
                cid,
                layer: Some(2),
            },
        };
        assert!(matches!(bad.leaves(&blocks), Err(RepoError::InvalidMst(_))));
    }
}
