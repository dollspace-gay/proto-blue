//! Writable repository: the read-write counterpart to
//! [`crate::sync::VerifiedRepo`].
//!
//! Wraps a [`RepoStorage`] with a cached MST + signed commit and
//! exposes the write-path TS `@atproto/repo` ships: `create`,
//! `load`, `format_commit`, `apply_writes`, `format_init_commit`,
//! `format_resign_commit`. Every mutation produces a fresh signed
//! commit; the storage layer is responsible for persisting the new
//! blocks atomically.
//!
//! All writes produce an in-memory [`CommitData`] that the caller
//! can either pass to [`Repo::apply_commit`] (persist via the repo's
//! storage) or emit as a CAR for sync.

use std::sync::Arc;

use proto_blue_common::next_tid;
use proto_blue_crypto::Signer;
use proto_blue_lex_cbor::cid_for_lex;
use proto_blue_lex_data::{Cid, LexValue};

use crate::block_map::BlockMap;
use crate::commit::{SignedCommit, UnsignedCommit, sign_commit};
use crate::data_key::parse_data_key;
use crate::error::RepoError;
use crate::mst::MstNode;
use crate::storage::RepoStorage;

/// A single write operation against a repo.
#[derive(Debug, Clone)]
pub enum RepoWrite {
    /// Create a record at `<collection>/<rkey>`. Fails if the key
    /// already exists.
    Create {
        collection: String,
        rkey: String,
        value: LexValue,
    },
    /// Update the record at `<collection>/<rkey>`. Fails if the key
    /// doesn't exist.
    Update {
        collection: String,
        rkey: String,
        value: LexValue,
    },
    /// Delete the record at `<collection>/<rkey>`.
    Delete { collection: String, rkey: String },
}

impl RepoWrite {
    fn key(&self) -> String {
        match self {
            Self::Create {
                collection, rkey, ..
            }
            | Self::Update {
                collection, rkey, ..
            }
            | Self::Delete { collection, rkey } => format!("{collection}/{rkey}"),
        }
    }
}

/// The result of [`Repo::format_commit`] — a fresh signed commit
/// plus the block set that must be persisted for the new state to
/// be reachable.
#[derive(Debug, Clone)]
pub struct CommitData {
    /// CID of the new signed commit.
    pub commit_cid: Cid,
    /// The new signed commit itself.
    pub commit: SignedCommit,
    /// Every new block needed for the commit: the commit block,
    /// new / updated MST nodes, and the record blocks for creates
    /// and updates. Does NOT include unchanged blocks.
    pub blocks: BlockMap,
    /// CIDs that are no longer referenced after this commit (stale
    /// MST nodes, replaced records). Useful for GC policies.
    pub removed_cids: Vec<Cid>,
}

/// A writable repository view.
///
/// Holds a cached in-memory MST + parent commit pointer. Writes go
/// through `format_commit` (compute a new commit without
/// persisting) and `apply_commit` (persist via the storage layer).
/// `apply_writes` is the combined one-shot.
pub struct Repo {
    storage: Arc<dyn RepoStorage>,
    did: String,
    commit_cid: Option<Cid>,
    commit: Option<SignedCommit>,
    mst: MstNode,
}

impl Repo {
    /// The repo owner's DID.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.did
    }

    /// CID of the current signed commit. `None` for an empty repo
    /// (no commits yet).
    #[must_use]
    pub const fn commit_cid(&self) -> Option<&Cid> {
        self.commit_cid.as_ref()
    }

    /// The current signed commit, if any.
    #[must_use]
    pub const fn commit(&self) -> Option<&SignedCommit> {
        self.commit.as_ref()
    }

    /// The current MST.
    #[must_use]
    pub const fn mst(&self) -> &MstNode {
        &self.mst
    }

    /// Load an existing repo from storage.
    ///
    /// Expects the storage to hold a valid signed commit at
    /// `storage.get_root()` and every MST block it points to.
    pub fn load(storage: Arc<dyn RepoStorage>) -> Result<Self, RepoError> {
        let commit_cid = storage
            .get_root()?
            .ok_or_else(|| RepoError::Storage("empty storage; use Repo::create".into()))?;
        let commit_val = storage.read_obj(&commit_cid)?;
        let commit = SignedCommit::from_lex_value(&commit_val)?;
        let mst = load_mst(&*storage, &commit.data)?;
        Ok(Self {
            storage,
            did: commit.did.clone(),
            commit_cid: Some(commit_cid),
            commit: Some(commit),
            mst,
        })
    }

    /// Create a fresh repo: signs an initial empty commit and
    /// persists it through `storage`.
    ///
    /// On success the storage holds exactly the init commit block +
    /// the empty MST root block; the repo's in-memory state matches.
    pub fn create(
        storage: Arc<dyn RepoStorage>,
        did: String,
        signer: &dyn Signer,
    ) -> Result<Self, RepoError> {
        // Empty MST → root CID of the empty node.
        let empty_mst = MstNode::empty();
        let (mst_root, mst_blocks) = empty_mst.get_all_blocks()?;

        let rev = next_tid(None).to_string();
        let unsigned = UnsignedCommit::new(did.clone(), mst_root, rev, None);
        let signed_commit = sign_commit(&unsigned, signer)?;
        let commit_cid = signed_commit.cid()?;

        let mut blocks = mst_blocks;
        let commit_bytes = proto_blue_lex_cbor::encode(&signed_commit.to_lex_value())?;
        blocks.set(commit_cid.clone(), commit_bytes);

        storage.apply_commit(commit_cid.clone(), &blocks)?;

        Ok(Self {
            storage,
            did,
            commit_cid: Some(commit_cid),
            commit: Some(signed_commit),
            mst: empty_mst,
        })
    }

    /// Compute the commit that would result from applying `writes`
    /// **without persisting it**. Returns a [`CommitData`] the
    /// caller can either apply via [`Self::apply_commit`] or emit
    /// as a CAR for sync.
    ///
    /// This is the core of the write path — split from `apply_commit`
    /// so callers that need to dry-run, diff, or emit the commit
    /// elsewhere (firehose, git-style staging) can do so without
    /// mutating storage.
    pub fn format_commit(
        &self,
        writes: &[RepoWrite],
        signer: &dyn Signer,
    ) -> Result<CommitData, RepoError> {
        // Apply each write to a fresh MST, tracking removed CIDs.
        let mut new_mst = self.mst.clone();
        let mut touched_record_blocks = BlockMap::new();

        for write in writes {
            // Validate key shape up front — catches bad NSIDs /
            // malformed rkeys before any tree manipulation.
            parse_data_key(&write.key())
                .map_err(|e| RepoError::InvalidMstKey(format!("invalid data key: {e}")))?;
            match write {
                RepoWrite::Create { value, .. } => {
                    let key = write.key();
                    if new_mst.get(&key).is_some() {
                        return Err(RepoError::KeyAlreadyExists(key));
                    }
                    let cid = cid_for_lex(value)?;
                    let bytes = proto_blue_lex_cbor::encode(value)?;
                    touched_record_blocks.set(cid.clone(), bytes);
                    new_mst = new_mst.add(&key, cid)?;
                }
                RepoWrite::Update { value, .. } => {
                    let key = write.key();
                    if new_mst.get(&key).is_none() {
                        return Err(RepoError::KeyNotFound(key));
                    }
                    let cid = cid_for_lex(value)?;
                    let bytes = proto_blue_lex_cbor::encode(value)?;
                    touched_record_blocks.set(cid.clone(), bytes);
                    new_mst = new_mst.update(&key, cid)?;
                }
                RepoWrite::Delete { .. } => {
                    let key = write.key();
                    new_mst = new_mst.delete(&key)?;
                }
            }
        }

        // Serialise the new MST into a fresh BlockMap.
        let (mst_root, mst_blocks) = new_mst.get_all_blocks()?;

        // Diff: any block present in the old MST but not the new MST
        // is "removed". `old_cids` / `new_cids` are small relative to
        // record payloads so the double-walk is fine.
        let old_cids = self.mst.all_cids()?;
        let new_cids = new_mst.all_cids()?;
        let removed_cids: Vec<Cid> = old_cids
            .iter()
            .filter(|c| !new_cids.has(c))
            .cloned()
            .collect();

        // Build the new commit.
        let rev = next_tid(None).to_string();
        let unsigned =
            UnsignedCommit::new(self.did.clone(), mst_root, rev, self.commit_cid.clone());
        let signed_commit = sign_commit(&unsigned, signer)?;
        let commit_cid = signed_commit.cid()?;

        // Merge: new MST blocks + record blocks + the commit itself.
        let mut blocks = mst_blocks;
        for (cid, bytes) in touched_record_blocks.iter() {
            blocks.set(cid.clone(), bytes.to_vec());
        }
        let commit_bytes = proto_blue_lex_cbor::encode(&signed_commit.to_lex_value())?;
        blocks.set(commit_cid.clone(), commit_bytes);

        Ok(CommitData {
            commit_cid,
            commit: signed_commit,
            blocks,
            removed_cids,
        })
    }

    /// Persist a [`CommitData`] through the storage layer and advance
    /// the in-memory state.
    pub fn apply_commit(&mut self, data: CommitData) -> Result<(), RepoError> {
        self.storage
            .apply_commit(data.commit_cid.clone(), &data.blocks)?;
        // Rebuild our cached MST pointer from the new commit's data CID.
        self.mst = load_mst(&*self.storage, &data.commit.data)?;
        self.commit_cid = Some(data.commit_cid);
        self.commit = Some(data.commit);
        Ok(())
    }

    /// Atomically format + apply `writes`. Combines
    /// [`Self::format_commit`] and [`Self::apply_commit`].
    pub fn apply_writes(
        &mut self,
        writes: &[RepoWrite],
        signer: &dyn Signer,
    ) -> Result<CommitData, RepoError> {
        let data = self.format_commit(writes, signer)?;
        // Clone so we can return the pre-apply CommitData (CAR emitters
        // often want the raw BlockMap).
        let clone = CommitData {
            commit_cid: data.commit_cid.clone(),
            commit: data.commit.clone(),
            blocks: {
                let mut b = BlockMap::new();
                for (c, v) in data.blocks.iter() {
                    b.set(c.clone(), v.to_vec());
                }
                b
            },
            removed_cids: data.removed_cids.clone(),
        };
        self.apply_commit(data)?;
        Ok(clone)
    }

    /// Re-sign the current commit with a different signer — e.g.
    /// after a signing-key rotation. Produces a new commit with a
    /// fresh `rev` but the same `data` CID, chained as the child of
    /// the current commit.
    pub fn format_resign_commit(&self, signer: &dyn Signer) -> Result<CommitData, RepoError> {
        let data_cid = self
            .commit
            .as_ref()
            .ok_or_else(|| RepoError::Storage("cannot resign an empty repo".into()))?
            .data
            .clone();
        let rev = next_tid(None).to_string();
        let unsigned =
            UnsignedCommit::new(self.did.clone(), data_cid, rev, self.commit_cid.clone());
        let signed_commit = sign_commit(&unsigned, signer)?;
        let commit_cid = signed_commit.cid()?;

        // The MST blocks are already in storage; only the new commit
        // block needs to be written.
        let mut blocks = BlockMap::new();
        let bytes = proto_blue_lex_cbor::encode(&signed_commit.to_lex_value())?;
        blocks.set(commit_cid.clone(), bytes);

        Ok(CommitData {
            commit_cid,
            commit: signed_commit,
            blocks,
            removed_cids: Vec::new(),
        })
    }

    /// Read a record by collection + rkey. Returns `None` if the
    /// key doesn't exist.
    pub fn get_record(&self, collection: &str, rkey: &str) -> Result<Option<LexValue>, RepoError> {
        let key = format!("{collection}/{rkey}");
        let Some(cid) = self.mst.get(&key) else {
            return Ok(None);
        };
        Ok(Some(self.storage.read_obj(&cid)?))
    }
}

/// Load an MST rooted at `data_cid` by walking through the storage.
fn load_mst(storage: &dyn RepoStorage, data_cid: &Cid) -> Result<MstNode, RepoError> {
    // Collect every block the MST root transitively references.
    let mut blocks = BlockMap::new();
    collect_mst_blocks(storage, data_cid, &mut blocks)?;
    MstNode::load(data_cid, &blocks)
}

fn collect_mst_blocks(
    storage: &dyn RepoStorage,
    cid: &Cid,
    out: &mut BlockMap,
) -> Result<(), RepoError> {
    if out.has(cid) {
        return Ok(());
    }
    let bytes = storage
        .get_block(cid)?
        .ok_or_else(|| RepoError::MissingBlock(cid.clone()))?;
    // Decode just enough to find child-tree CIDs.
    let value = proto_blue_lex_cbor::decode(&bytes)?;
    out.set(cid.clone(), bytes);

    // MST nodes are `{e: [...], l: <cid>?}` — walk `l` and each
    // entry's `t` (tree) CID if present.
    if let LexValue::Map(m) = &value {
        if let Some(LexValue::Cid(l)) = m.get("l") {
            collect_mst_blocks(storage, l, out)?;
        }
        if let Some(LexValue::Array(entries)) = m.get("e") {
            for entry in entries {
                if let LexValue::Map(em) = entry
                    && let Some(LexValue::Cid(t)) = em.get("t")
                {
                    collect_mst_blocks(storage, t, out)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryBlockstore;
    use proto_blue_crypto::{K256Keypair, Keypair};

    fn signer() -> K256Keypair {
        K256Keypair::generate()
    }

    #[test]
    fn create_empty_repo_and_load_back() {
        let s = Arc::new(MemoryBlockstore::new());
        let k = signer();
        let did = k.did();
        let repo = Repo::create(s.clone(), did.clone(), &k).unwrap();
        assert_eq!(repo.did(), did);
        assert!(repo.commit_cid().is_some());
        assert_eq!(repo.mst().leaves().len(), 0);

        // Re-load from the same storage.
        let reloaded = Repo::load(s).unwrap();
        assert_eq!(reloaded.did(), did);
        assert_eq!(reloaded.commit_cid(), repo.commit_cid());
    }

    #[test]
    fn create_then_create_record_round_trips() {
        let s = Arc::new(MemoryBlockstore::new());
        let k = signer();
        let mut repo = Repo::create(s.clone(), k.did(), &k).unwrap();

        let record = LexValue::String("hello".into());
        let write = RepoWrite::Create {
            collection: "com.example.item".into(),
            rkey: "abc".into(),
            value: record.clone(),
        };
        let data = repo.apply_writes(&[write], &k).unwrap();
        assert_ne!(
            data.commit_cid,
            *repo
                .commit()
                .unwrap()
                .unsigned()
                .prev
                .as_ref()
                .unwrap_or(&data.commit_cid)
        );

        let out = repo.get_record("com.example.item", "abc").unwrap();
        assert_eq!(out, Some(record));

        // Re-load to confirm storage persisted everything.
        let loaded = Repo::load(s).unwrap();
        assert_eq!(loaded.mst().leaves().len(), 1);
    }

    #[test]
    fn update_record_replaces_value() {
        let s = Arc::new(MemoryBlockstore::new());
        let k = signer();
        let mut repo = Repo::create(s, k.did(), &k).unwrap();
        repo.apply_writes(
            &[RepoWrite::Create {
                collection: "com.example.t".into(),
                rkey: "x".into(),
                value: LexValue::Integer(1),
            }],
            &k,
        )
        .unwrap();
        repo.apply_writes(
            &[RepoWrite::Update {
                collection: "com.example.t".into(),
                rkey: "x".into(),
                value: LexValue::Integer(2),
            }],
            &k,
        )
        .unwrap();
        let got = repo.get_record("com.example.t", "x").unwrap().unwrap();
        assert_eq!(got, LexValue::Integer(2));
    }

    #[test]
    fn delete_record_removes_from_mst() {
        let s = Arc::new(MemoryBlockstore::new());
        let k = signer();
        let mut repo = Repo::create(s, k.did(), &k).unwrap();
        repo.apply_writes(
            &[RepoWrite::Create {
                collection: "com.example.t".into(),
                rkey: "x".into(),
                value: LexValue::Integer(1),
            }],
            &k,
        )
        .unwrap();
        repo.apply_writes(
            &[RepoWrite::Delete {
                collection: "com.example.t".into(),
                rkey: "x".into(),
            }],
            &k,
        )
        .unwrap();
        assert_eq!(repo.mst().leaves().len(), 0);
        assert!(repo.get_record("com.example.t", "x").unwrap().is_none());
    }

    #[test]
    fn create_twice_errors_key_already_exists() {
        let s = Arc::new(MemoryBlockstore::new());
        let k = signer();
        let mut repo = Repo::create(s, k.did(), &k).unwrap();
        repo.apply_writes(
            &[RepoWrite::Create {
                collection: "com.example.t".into(),
                rkey: "x".into(),
                value: LexValue::Integer(1),
            }],
            &k,
        )
        .unwrap();
        let err = repo
            .apply_writes(
                &[RepoWrite::Create {
                    collection: "com.example.t".into(),
                    rkey: "x".into(),
                    value: LexValue::Integer(2),
                }],
                &k,
            )
            .unwrap_err();
        assert!(matches!(err, RepoError::KeyAlreadyExists(_)));
    }

    #[test]
    fn update_missing_key_errors() {
        let s = Arc::new(MemoryBlockstore::new());
        let k = signer();
        let mut repo = Repo::create(s, k.did(), &k).unwrap();
        let err = repo
            .apply_writes(
                &[RepoWrite::Update {
                    collection: "com.example.t".into(),
                    rkey: "missing".into(),
                    value: LexValue::Integer(1),
                }],
                &k,
            )
            .unwrap_err();
        assert!(matches!(err, RepoError::KeyNotFound(_)));
    }

    #[test]
    fn batch_writes_atomic_commit() {
        let s = Arc::new(MemoryBlockstore::new());
        let k = signer();
        let mut repo = Repo::create(s, k.did(), &k).unwrap();
        let writes = vec![
            RepoWrite::Create {
                collection: "com.example.t".into(),
                rkey: "a".into(),
                value: LexValue::Integer(1),
            },
            RepoWrite::Create {
                collection: "com.example.t".into(),
                rkey: "b".into(),
                value: LexValue::Integer(2),
            },
        ];
        let data = repo.apply_writes(&writes, &k).unwrap();
        // Two new records + new MST node + commit = at least 3 blocks.
        assert!(data.blocks.len() >= 3);
        assert_eq!(repo.mst().leaves().len(), 2);
    }

    #[test]
    fn format_resign_commit_keeps_data_cid() {
        let s = Arc::new(MemoryBlockstore::new());
        let k = signer();
        let mut repo = Repo::create(s, k.did(), &k).unwrap();
        // Apply a write so the data CID is non-trivial.
        repo.apply_writes(
            &[RepoWrite::Create {
                collection: "com.example.t".into(),
                rkey: "x".into(),
                value: LexValue::String("hi".into()),
            }],
            &k,
        )
        .unwrap();
        let original_data = repo.commit().unwrap().data.clone();

        // Re-sign — the data CID must stay, the commit CID must change.
        let new_key = signer();
        let resigned = repo.format_resign_commit(&new_key).unwrap();
        assert_eq!(resigned.commit.data, original_data);
        assert_ne!(Some(resigned.commit_cid), repo.commit_cid().cloned());
    }
}
