//! Diff two MSTs into structured add/update/delete lists.
//!
//! This is the primitive that firehose consumers and repo-sync clients
//! use to understand what changed between two commits of the same repo.
//! Every commit advances the MST root; comparing the old root to the new
//! one yields:
//!
//! - **adds**    — keys that exist only in the new tree.
//! - **updates** — keys that exist in both but point to different CIDs.
//! - **deletes** — keys that exist only in the old tree.
//!
//! Plus two block-level CID sets:
//!
//! - `new_mst_blocks` — MST node blocks that the new tree has and the
//!   old tree did not (the caller needs to fetch or store these).
//! - `new_leaf_cids`  — record CIDs that the new tree references and the
//!   old tree did not.
//! - `removed_cids`   — record and MST-block CIDs that were in the old
//!   tree but no longer referenced by the new one.
//!
//! Implementation strategy: the TS reference uses an interleaved tree-
//! walker that emits diff deltas directly. We take a simpler path — flat
//! ordered leaf lists via `MstNode::leaves()` + block-set diffing via
//! `get_all_blocks()` — which is easier to reason about and still
//! `O((n + m) log n)` for trees with `n` and `m` leaves. The result is
//! identical.

use std::collections::BTreeMap;

use proto_blue_lex_data::Cid;

use crate::block_map::BlockMap;
use crate::cid_set::CidSet;
use crate::error::RepoError;
use crate::mst::MstNode;

/// A key that exists in the new tree but not the old.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataAdd {
    pub key: String,
    pub cid: Cid,
}

/// A key that exists in both trees but points to a different CID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataUpdate {
    pub key: String,
    pub prev: Cid,
    pub cid: Cid,
}

/// A key that exists in the old tree but not the new.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDelete {
    pub key: String,
    pub cid: Cid,
}

/// The full diff between two MSTs.
#[derive(Debug, Clone, Default)]
pub struct DataDiff {
    /// Keys added, keyed by record key.
    pub adds: BTreeMap<String, DataAdd>,
    /// Keys updated.
    pub updates: BTreeMap<String, DataUpdate>,
    /// Keys deleted.
    pub deletes: BTreeMap<String, DataDelete>,
    /// MST node blocks present in the new tree but not the old.
    pub new_mst_blocks: BlockMap,
    /// Record CIDs newly referenced by the new tree.
    pub new_leaf_cids: CidSet,
    /// Record or MST-block CIDs no longer referenced.
    pub removed_cids: CidSet,
}

impl DataDiff {
    /// Diff `curr` against `prev`. Pass `prev = None` for a "null diff"
    /// (the new tree as an add-only view). This matches TS `mstDiff`.
    pub fn of(curr: &MstNode, prev: Option<&MstNode>) -> Result<DataDiff, RepoError> {
        match prev {
            None => null_diff(curr),
            Some(prev) => full_diff(curr, prev),
        }
    }

    /// Return the add list (in sorted-by-key order).
    pub fn add_list(&self) -> Vec<&DataAdd> {
        self.adds.values().collect()
    }

    /// Return the update list (in sorted-by-key order).
    pub fn update_list(&self) -> Vec<&DataUpdate> {
        self.updates.values().collect()
    }

    /// Return the delete list (in sorted-by-key order).
    pub fn delete_list(&self) -> Vec<&DataDelete> {
        self.deletes.values().collect()
    }

    /// Union of all keys touched by this diff (adds ∪ updates ∪ deletes),
    /// deduplicated.
    pub fn updated_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = Vec::new();
        keys.extend(self.adds.keys().cloned());
        keys.extend(self.updates.keys().cloned());
        keys.extend(self.deletes.keys().cloned());
        keys.sort();
        keys.dedup();
        keys
    }

    /// `true` if this diff is empty (nothing added, updated, or deleted).
    pub fn is_empty(&self) -> bool {
        self.adds.is_empty() && self.updates.is_empty() && self.deletes.is_empty()
    }
}

/// "Null diff": treat the entire new tree as adds. Used when there is
/// no previous tree (e.g. the first commit in a repo).
fn null_diff(curr: &MstNode) -> Result<DataDiff, RepoError> {
    let mut diff = DataDiff::default();
    for leaf in curr.leaves() {
        diff.new_leaf_cids.add(leaf.value.clone());
        diff.adds.insert(
            leaf.key.clone(),
            DataAdd {
                key: leaf.key,
                cid: leaf.value,
            },
        );
    }
    // Every MST block in the new tree is new.
    let (_, blocks) = curr.get_all_blocks()?;
    diff.new_mst_blocks = blocks;
    Ok(diff)
}

/// Compute the full diff of `curr` against `prev`.
fn full_diff(curr: &MstNode, prev: &MstNode) -> Result<DataDiff, RepoError> {
    let mut diff = DataDiff::default();

    // ── Leaf-level diff via ordered-key merge ──
    //
    // `leaves()` returns leaves sorted by key (MST invariant), so this
    // is a linear two-pointer merge.
    let curr_leaves = curr.leaves();
    let prev_leaves = prev.leaves();
    let mut ci = 0usize;
    let mut pi = 0usize;
    while ci < curr_leaves.len() && pi < prev_leaves.len() {
        let c = &curr_leaves[ci];
        let p = &prev_leaves[pi];
        match c.key.cmp(&p.key) {
            std::cmp::Ordering::Equal => {
                // Same key. If the value CID changed, it's an update;
                // otherwise skip silently.
                if c.value.to_string_base32() != p.value.to_string_base32() {
                    diff.removed_cids.add(p.value.clone());
                    diff.new_leaf_cids.add(c.value.clone());
                    diff.updates.insert(
                        c.key.clone(),
                        DataUpdate {
                            key: c.key.clone(),
                            prev: p.value.clone(),
                            cid: c.value.clone(),
                        },
                    );
                }
                ci += 1;
                pi += 1;
            }
            std::cmp::Ordering::Less => {
                // Key only in curr -> add.
                diff.new_leaf_cids.add(c.value.clone());
                diff.adds.insert(
                    c.key.clone(),
                    DataAdd {
                        key: c.key.clone(),
                        cid: c.value.clone(),
                    },
                );
                ci += 1;
            }
            std::cmp::Ordering::Greater => {
                // Key only in prev -> delete.
                diff.removed_cids.add(p.value.clone());
                diff.deletes.insert(
                    p.key.clone(),
                    DataDelete {
                        key: p.key.clone(),
                        cid: p.value.clone(),
                    },
                );
                pi += 1;
            }
        }
    }
    while ci < curr_leaves.len() {
        let c = &curr_leaves[ci];
        diff.new_leaf_cids.add(c.value.clone());
        diff.adds.insert(
            c.key.clone(),
            DataAdd {
                key: c.key.clone(),
                cid: c.value.clone(),
            },
        );
        ci += 1;
    }
    while pi < prev_leaves.len() {
        let p = &prev_leaves[pi];
        diff.removed_cids.add(p.value.clone());
        diff.deletes.insert(
            p.key.clone(),
            DataDelete {
                key: p.key.clone(),
                cid: p.value.clone(),
            },
        );
        pi += 1;
    }

    // ── Block-level diff: which MST nodes are new vs gone ──
    //
    // A block is "new" if the new tree produces it and the old tree did
    // not. A block is "removed" if the old tree produced it and the new
    // tree doesn't. We already hashed both trees via `get_all_blocks`
    // above for the leaves; re-use those block maps for this set diff.
    let (_, curr_blocks) = curr.get_all_blocks()?;
    let (_, prev_blocks) = prev.get_all_blocks()?;

    for (cid_b32, bytes) in curr_blocks.iter_entries() {
        if !prev_blocks.has_str(&cid_b32) {
            diff.new_mst_blocks.set(bytes.0.clone(), bytes.1.to_vec());
        }
    }
    for (cid_b32, entry) in prev_blocks.iter_entries() {
        if !curr_blocks.has_str(&cid_b32) {
            diff.removed_cids.add(entry.0.clone());
        }
    }

    Ok(diff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_blue_lex_cbor::cid_for_lex;
    use proto_blue_lex_data::LexValue;

    fn cid_for(bytes: &[u8]) -> Cid {
        cid_for_lex(&LexValue::Bytes(bytes.to_vec())).unwrap()
    }

    // ── null-diff path ──

    #[test]
    fn null_diff_of_empty_tree_is_empty() {
        let mst = MstNode::empty();
        let diff = DataDiff::of(&mst, None).unwrap();
        assert!(diff.is_empty());
        assert!(diff.adds.is_empty());
    }

    #[test]
    fn null_diff_treats_every_leaf_as_add() {
        let cid_a = cid_for(b"a");
        let cid_b = cid_for(b"b");
        let mst = MstNode::empty();
        let mst = mst.add("coll/a", cid_a.clone()).unwrap();
        let mst = mst.add("coll/b", cid_b.clone()).unwrap();

        let diff = DataDiff::of(&mst, None).unwrap();
        assert_eq!(diff.adds.len(), 2);
        assert!(diff.updates.is_empty());
        assert!(diff.deletes.is_empty());
        assert!(diff.new_leaf_cids.has(&cid_a));
        assert!(diff.new_leaf_cids.has(&cid_b));
        assert!(diff.removed_cids.is_empty());
    }

    // ── full-diff path ──

    #[test]
    fn full_diff_empty_vs_empty_is_empty() {
        let empty = MstNode::empty();
        let diff = DataDiff::of(&empty, Some(&empty)).unwrap();
        assert!(diff.is_empty());
        assert!(diff.new_mst_blocks.is_empty());
        assert!(diff.new_leaf_cids.is_empty());
        assert!(diff.removed_cids.is_empty());
    }

    #[test]
    fn full_diff_add_one_key() {
        let cid = cid_for(b"v");
        let prev = MstNode::empty();
        let curr = prev.clone().add("coll/k", cid.clone()).unwrap();

        let diff = DataDiff::of(&curr, Some(&prev)).unwrap();
        assert_eq!(diff.adds.len(), 1);
        assert!(diff.adds.contains_key("coll/k"));
        assert!(diff.updates.is_empty());
        assert!(diff.deletes.is_empty());
        assert!(diff.new_leaf_cids.has(&cid));
    }

    #[test]
    fn full_diff_delete_one_key() {
        let cid = cid_for(b"v");
        let prev = MstNode::empty().add("coll/k", cid.clone()).unwrap();
        let curr = prev.delete("coll/k").unwrap();

        let diff = DataDiff::of(&curr, Some(&prev)).unwrap();
        assert!(diff.adds.is_empty());
        assert!(diff.updates.is_empty());
        assert_eq!(diff.deletes.len(), 1);
        assert_eq!(diff.deletes["coll/k"].cid, cid);
        assert!(diff.removed_cids.has(&cid));
    }

    #[test]
    fn full_diff_update_one_key() {
        let cid_old = cid_for(b"old");
        let cid_new = cid_for(b"new");
        let prev = MstNode::empty().add("coll/k", cid_old.clone()).unwrap();
        let curr = prev.update("coll/k", cid_new.clone()).unwrap();

        let diff = DataDiff::of(&curr, Some(&prev)).unwrap();
        assert!(diff.adds.is_empty());
        assert_eq!(diff.updates.len(), 1);
        let upd = &diff.updates["coll/k"];
        assert_eq!(upd.prev, cid_old);
        assert_eq!(upd.cid, cid_new);
        assert!(diff.deletes.is_empty());
        assert!(diff.new_leaf_cids.has(&cid_new));
        assert!(diff.removed_cids.has(&cid_old));
    }

    #[test]
    fn full_diff_no_change_when_curr_equals_prev() {
        let mst = MstNode::empty()
            .add("coll/a", cid_for(b"a"))
            .unwrap()
            .add("coll/b", cid_for(b"b"))
            .unwrap();
        let diff = DataDiff::of(&mst, Some(&mst)).unwrap();
        assert!(diff.is_empty());
        assert!(diff.new_mst_blocks.is_empty());
        assert!(diff.removed_cids.is_empty());
    }

    #[test]
    fn full_diff_mixed_ops() {
        // Prev: {a, b, c}. Curr: {a' (updated), b (same), d (new)}.
        // Expected: updates={a}, adds={d}, deletes={c}, b no-op.
        let cid_a1 = cid_for(b"a1");
        let cid_a2 = cid_for(b"a2");
        let cid_b = cid_for(b"b");
        let cid_c = cid_for(b"c");
        let cid_d = cid_for(b"d");

        let prev = MstNode::empty()
            .add("coll/a", cid_a1.clone())
            .unwrap()
            .add("coll/b", cid_b.clone())
            .unwrap()
            .add("coll/c", cid_c.clone())
            .unwrap();
        let curr = MstNode::empty()
            .add("coll/a", cid_a2.clone())
            .unwrap()
            .add("coll/b", cid_b.clone())
            .unwrap()
            .add("coll/d", cid_d.clone())
            .unwrap();

        let diff = DataDiff::of(&curr, Some(&prev)).unwrap();

        assert_eq!(diff.updates.len(), 1);
        assert_eq!(diff.updates["coll/a"].prev, cid_a1);
        assert_eq!(diff.updates["coll/a"].cid, cid_a2);

        assert_eq!(diff.adds.len(), 1);
        assert_eq!(diff.adds["coll/d"].cid, cid_d);

        assert_eq!(diff.deletes.len(), 1);
        assert_eq!(diff.deletes["coll/c"].cid, cid_c);

        assert!(diff.new_leaf_cids.has(&cid_a2));
        assert!(diff.new_leaf_cids.has(&cid_d));
        assert!(
            !diff.new_leaf_cids.has(&cid_b),
            "unchanged leaf must not appear in new_leaf_cids"
        );

        assert!(diff.removed_cids.has(&cid_a1));
        assert!(diff.removed_cids.has(&cid_c));
    }

    #[test]
    fn updated_keys_dedupe() {
        let cid1 = cid_for(b"1");
        let cid2 = cid_for(b"2");
        let prev = MstNode::empty().add("coll/x", cid1.clone()).unwrap();
        let curr = prev
            .clone()
            .update("coll/x", cid2.clone())
            .unwrap()
            .add("coll/y", cid2.clone())
            .unwrap();
        let diff = DataDiff::of(&curr, Some(&prev)).unwrap();
        let keys = diff.updated_keys();
        assert_eq!(keys, vec!["coll/x".to_string(), "coll/y".to_string()]);
    }

    #[test]
    fn full_diff_round_trips_block_level_sets() {
        // After applying `diff.new_mst_blocks` and removing
        // `diff.removed_cids` from a working copy of the prev blocks,
        // we must be able to reach the same set of curr blocks.
        let cid_a = cid_for(b"a");
        let cid_b = cid_for(b"b");
        let prev = MstNode::empty().add("coll/a", cid_a).unwrap();
        let curr = prev.clone().add("coll/b", cid_b).unwrap();

        let diff = DataDiff::of(&curr, Some(&prev)).unwrap();
        let (_, prev_blocks) = prev.get_all_blocks().unwrap();
        let (curr_root, curr_blocks) = curr.get_all_blocks().unwrap();

        let mut working = prev_blocks;
        // Apply removals.
        for cid in diff.removed_cids.iter() {
            working.delete(cid);
        }
        // Apply additions.
        for (_, (cid, bytes)) in diff.new_mst_blocks.iter_entries() {
            working.set(cid.clone(), bytes.to_vec());
        }

        assert!(
            working.has(&curr_root),
            "reconstructed blocks must contain the new root"
        );
        // Every curr block must now be in working.
        for (cid_str, _) in curr_blocks.iter_entries() {
            assert!(
                working.has_str(&cid_str),
                "curr block {cid_str} missing from reconstructed set"
            );
        }
    }
}
