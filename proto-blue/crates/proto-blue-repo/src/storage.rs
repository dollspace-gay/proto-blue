//! Block storage trait + in-memory implementation.
//!
//! `RepoStorage` is the abstraction over "where do the CBOR blocks
//! (commits, MST nodes, records) live". `Repo` talks to it to load
//! existing state and persist new commits; the caller supplies the
//! concrete implementation (in-memory, on-disk, database-backed).
//!
//! Mirrors TS `@atproto/repo`'s `RepoStorage` / `ReadableBlockstore`
//! interfaces, collapsed into a single trait with a separate
//! read-only view exposed via the `ReadableStorage` helper methods.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use proto_blue_lex_data::{Cid, LexValue};

use crate::block_map::BlockMap;
use crate::error::RepoError;

/// Persistence layer for a repository.
///
/// Implementations store DAG-CBOR blocks keyed by CID and remember
/// the current commit root. Writes are expected to be atomic at the
/// block-batch level (`put_blocks`) and the root update
/// (`update_root`).
pub trait RepoStorage: Send + Sync {
    /// Fetch raw bytes for a block, or `None` if unknown.
    fn get_block(&self, cid: &Cid) -> Result<Option<Vec<u8>>, RepoError>;

    /// Fetch a block and decode it as a [`LexValue`]. Returns
    /// `Err(MissingBlock)` when the CID is not present.
    fn read_obj(&self, cid: &Cid) -> Result<LexValue, RepoError> {
        let bytes = self
            .get_block(cid)?
            .ok_or_else(|| RepoError::MissingBlock(cid.clone()))?;
        Ok(proto_blue_lex_cbor::decode(&bytes)?)
    }

    /// Store a single block under its CID. No-op if the CID is
    /// already present (content-addressed storage is idempotent).
    fn put_block(&self, cid: Cid, bytes: Vec<u8>) -> Result<(), RepoError>;

    /// Store every block in a [`BlockMap`] atomically.
    ///
    /// Default impl loops over [`put_block`]; backends that support
    /// transactional writes should override.
    fn put_blocks(&self, blocks: &BlockMap) -> Result<(), RepoError> {
        for (cid, bytes) in blocks.iter() {
            self.put_block(cid.clone(), bytes.to_vec())?;
        }
        Ok(())
    }

    /// Return the CID of the current signed commit, or `None` for
    /// an empty repo.
    fn get_root(&self) -> Result<Option<Cid>, RepoError>;

    /// Atomically update the commit root pointer.
    fn update_root(&self, new_root: Cid) -> Result<(), RepoError>;

    /// Convenience: store every block in `blocks` and then update
    /// the root in one call. Callers expect this to be atomic, so
    /// backends that can offer a real transaction should override.
    fn apply_commit(&self, new_root: Cid, blocks: &BlockMap) -> Result<(), RepoError> {
        self.put_blocks(blocks)?;
        self.update_root(new_root)?;
        Ok(())
    }
}

/// In-memory implementation of [`RepoStorage`], useful for tests,
/// ephemeral tools, and offline repo manipulation.
///
/// Thread-safe via a single `Mutex` around the inner map — fine for
/// single-process usage. For higher-concurrency workloads swap in a
/// `DashMap`-backed variant or a real database backend.
#[derive(Default)]
pub struct MemoryBlockstore {
    inner: Arc<Mutex<MemoryInner>>,
}

#[derive(Default)]
struct MemoryInner {
    blocks: HashMap<Cid, Vec<u8>>,
    root: Option<Cid>,
}

impl MemoryBlockstore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a store pre-populated with a [`BlockMap`] and an
    /// optional root commit CID — typical usage after reading a CAR.
    #[must_use]
    pub fn from_blocks(blocks: BlockMap, root: Option<Cid>) -> Self {
        let mut map = HashMap::new();
        for (cid, bytes) in blocks.iter() {
            map.insert(cid.clone(), bytes.to_vec());
        }
        Self {
            inner: Arc::new(Mutex::new(MemoryInner { blocks: map, root })),
        }
    }

    /// Number of blocks currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().blocks.len()
    }

    /// `true` when no blocks have been stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot the current contents as a [`BlockMap`]. Useful for
    /// emitting a CAR.
    #[must_use]
    pub fn snapshot(&self) -> BlockMap {
        let inner = self.inner.lock().unwrap();
        let mut out = BlockMap::new();
        for (cid, bytes) in &inner.blocks {
            out.set(cid.clone(), bytes.clone());
        }
        out
    }
}

impl RepoStorage for MemoryBlockstore {
    fn get_block(&self, cid: &Cid) -> Result<Option<Vec<u8>>, RepoError> {
        Ok(self.inner.lock().unwrap().blocks.get(cid).cloned())
    }

    fn put_block(&self, cid: Cid, bytes: Vec<u8>) -> Result<(), RepoError> {
        self.inner.lock().unwrap().blocks.insert(cid, bytes);
        Ok(())
    }

    fn get_root(&self) -> Result<Option<Cid>, RepoError> {
        Ok(self.inner.lock().unwrap().root.clone())
    }

    fn update_root(&self, new_root: Cid) -> Result<(), RepoError> {
        self.inner.lock().unwrap().root = Some(new_root);
        Ok(())
    }

    fn apply_commit(&self, new_root: Cid, blocks: &BlockMap) -> Result<(), RepoError> {
        let mut inner = self.inner.lock().unwrap();
        for (cid, bytes) in blocks.iter() {
            inner.blocks.insert(cid.clone(), bytes.to_vec());
        }
        inner.root = Some(new_root);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get_block() {
        let store = MemoryBlockstore::new();
        let cid = Cid::for_raw(b"hello");
        store.put_block(cid.clone(), b"hello".to_vec()).unwrap();
        assert_eq!(store.get_block(&cid).unwrap(), Some(b"hello".to_vec()));
    }

    #[test]
    fn missing_block_returns_none() {
        let store = MemoryBlockstore::new();
        let cid = Cid::for_raw(b"nope");
        assert_eq!(store.get_block(&cid).unwrap(), None);
    }

    #[test]
    fn read_obj_decodes_cbor() {
        let store = MemoryBlockstore::new();
        let val = LexValue::String("x".into());
        let bytes = proto_blue_lex_cbor::encode(&val).unwrap();
        let cid = proto_blue_lex_cbor::cid_for_lex(&val).unwrap();
        store.put_block(cid.clone(), bytes).unwrap();
        let out = store.read_obj(&cid).unwrap();
        assert_eq!(out, val);
    }

    #[test]
    fn read_obj_missing_block_errors() {
        let store = MemoryBlockstore::new();
        let err = store.read_obj(&Cid::for_raw(b"x")).unwrap_err();
        assert!(matches!(err, RepoError::MissingBlock(_)));
    }

    #[test]
    fn root_pointer_is_tracked() {
        let store = MemoryBlockstore::new();
        assert!(store.get_root().unwrap().is_none());
        let cid = Cid::for_raw(b"root");
        store.update_root(cid.clone()).unwrap();
        assert_eq!(store.get_root().unwrap(), Some(cid));
    }

    #[test]
    fn apply_commit_is_atomic() {
        let store = MemoryBlockstore::new();
        let mut blocks = BlockMap::new();
        let val = LexValue::String("commit".into());
        let cid = blocks.add_value(&val).unwrap();
        store.apply_commit(cid.clone(), &blocks).unwrap();
        assert_eq!(store.get_root().unwrap(), Some(cid.clone()));
        assert!(store.get_block(&cid).unwrap().is_some());
    }

    #[test]
    fn from_blocks_pre_populates() {
        let mut blocks = BlockMap::new();
        let cid = blocks.add_value(&LexValue::String("x".into())).unwrap();
        let store = MemoryBlockstore::from_blocks(blocks, Some(cid.clone()));
        assert_eq!(store.get_root().unwrap(), Some(cid.clone()));
        assert!(store.get_block(&cid).unwrap().is_some());
    }

    #[test]
    fn snapshot_round_trips() {
        let store = MemoryBlockstore::new();
        let mut original = BlockMap::new();
        let c1 = original.add_value(&LexValue::String("a".into())).unwrap();
        let c2 = original.add_value(&LexValue::String("b".into())).unwrap();
        store.put_blocks(&original).unwrap();
        let snap = store.snapshot();
        assert!(snap.has(&c1));
        assert!(snap.has(&c2));
    }
}
