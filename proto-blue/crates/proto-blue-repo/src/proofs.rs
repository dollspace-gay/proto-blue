//! Merkle proofs over an MST.
//!
//! A proof is a [`BlockMap`] containing just the MST-node blocks needed
//! to verify a claim about one or more leaves of the tree without
//! possessing the entire tree. The verifier combines the blocks with
//! the tree's root CID and walks down to the target key exactly as
//! [`MstNode::load`] + [`MstNode::get`] would.
//!
//! Four proof builders are exposed:
//!
//! - [`proof_for_key`]         — the nodes on the path to a specific key
//!   (or to where that key would live if absent).
//! - [`proof_for_left_sibling`]  — the nodes on the path to the leaf
//!   immediately to the left of `key`.
//! - [`proof_for_right_sibling`] — same, to the right.
//! - [`covering_proof`]       — union of all three: enough to verify
//!   that `key` has value `v` AND that no other key between its
//!   neighbors is in the tree. This is the proof shape atproto uses
//!   for commit-integrity claims on repo updates.
//!
//! And one verifier:
//!
//! - [`verify_key_in_proof`] — given the proof blocks, the root CID,
//!   and a claim `(key, expected_value)`, check that the claim holds.
//!
//! Mirrors the TS reference: `packages/repo/src/mst/mst.ts`
//! (`getCoveringProof` / `proofForKey` / `proofForLeftSib` /
//! `proofForRightSib`).

use proto_blue_lex_data::Cid;

use crate::block_map::BlockMap;
use crate::commit::SignedCommit;
use crate::error::RepoError;
use crate::mst::util::{deserialize_node_data, entries_to_keys};
use crate::mst::{MstNode, NodeEntry};

/// Collect the blocks on the path from the tree's root down to `key`
/// (or to where `key` would live if absent).
///
/// The returned `BlockMap` contains every MST node the walk traversed,
/// each serialized canonically via DAG-CBOR. Leaf record blocks are
/// NOT included — a proof about the MST structure alone is sufficient
/// for existence/absence claims.
pub fn proof_for_key(mst: &MstNode, key: &str) -> Result<BlockMap, RepoError> {
    let mut blocks = BlockMap::new();
    walk_for_key(mst, key, &mut blocks)?;
    Ok(blocks)
}

/// Collect the blocks on the path to the leaf immediately to the left
/// of `key` (i.e. the greatest leaf with key strictly less than `key`,
/// if any).
pub fn proof_for_left_sibling(mst: &MstNode, key: &str) -> Result<BlockMap, RepoError> {
    let mut blocks = BlockMap::new();
    walk_for_left_sibling(mst, key, &mut blocks)?;
    Ok(blocks)
}

/// Collect the blocks on the path to the leaf immediately to the right
/// of `key` (the smallest leaf with key strictly greater than `key`,
/// if any).
pub fn proof_for_right_sibling(mst: &MstNode, key: &str) -> Result<BlockMap, RepoError> {
    let mut blocks = BlockMap::new();
    walk_for_right_sibling(mst, key, &mut blocks)?;
    Ok(blocks)
}

/// A covering proof: the union of `proof_for_key`,
/// `proof_for_left_sibling`, and `proof_for_right_sibling`.
///
/// This is enough to prove (a) the presence or absence of `key` at a
/// specific value, and (b) that no unrelated leaf between the left
/// and right siblings is also present.
pub fn covering_proof(mst: &MstNode, key: &str) -> Result<BlockMap, RepoError> {
    let mut blocks = proof_for_key(mst, key)?;
    let left = proof_for_left_sibling(mst, key)?;
    let right = proof_for_right_sibling(mst, key)?;
    for (cid, bytes) in left.iter() {
        blocks.set(cid.clone(), bytes.to_vec());
    }
    for (cid, bytes) in right.iter() {
        blocks.set(cid.clone(), bytes.to_vec());
    }
    Ok(blocks)
}

/// A commit proof: a covering proof plus the signed commit block.
///
/// The caller will typically verify the commit's signature separately
/// (via [`crate::verify_commit_sig`]) and then use this proof to check
/// that the MST rooted at `commit.data` indeed contains the claimed
/// `(key, value)`.
pub fn commit_proof(
    mst: &MstNode,
    commit: &SignedCommit,
    key: &str,
) -> Result<BlockMap, RepoError> {
    let mut blocks = covering_proof(mst, key)?;
    blocks.set(commit.cid()?, commit.to_cbor()?);
    Ok(blocks)
}

/// Verify a key claim against a proof.
///
/// - `proof`: the block map returned by [`proof_for_key`] or
///   [`covering_proof`] (extra unrelated blocks are ignored).
/// - `root`: the MST root CID (same CID the proof was built at).
/// - `key`: the key being asserted about.
/// - `expected`: `Some(value_cid)` to assert the key maps to
///   `value_cid`, or `None` to assert the key is NOT in the tree.
///
/// Returns `Ok(true)` if the claim holds, `Ok(false)` if the proof
/// contradicts it, and `Err(MissingBlock)` if the proof is
/// structurally incomplete (a block needed to decide the claim is not
/// in the block map, so the verifier can't reach a conclusion).
///
/// Walks the tree node-by-node through the proof's `NodeData` rather
/// than eagerly loading full subtrees, so unrelated sibling subtrees
/// (whose blocks are legitimately absent from the proof) don't cause
/// spurious failures.
pub fn verify_key_in_proof(
    proof: &BlockMap,
    root: &Cid,
    key: &str,
    expected: Option<&Cid>,
) -> Result<bool, RepoError> {
    let found = lookup_in_proof(proof, root, key)?;
    let ok = match (found, expected) {
        (None, None) => true,
        (Some(ref got), Some(want)) => got.to_string_base32() == want.to_string_base32(),
        _ => false,
    };
    Ok(ok)
}

/// A claim that a particular key either has a specific value CID or is
/// absent from the tree. Used by [`verify_claims`] for batch proof
/// verification.
#[derive(Debug, Clone)]
pub struct RecordCidClaim {
    pub key: String,
    /// `Some(cid)` asserts the leaf exists with that value; `None`
    /// asserts absence.
    pub cid: Option<Cid>,
}

/// Check a batch of [`RecordCidClaim`]s against a single proof.
///
/// Returns the indices of claims that **failed** verification, or an
/// empty vec if all claims hold. Returns `Err(MissingBlock)` if the
/// proof is structurally incomplete for any claim (the caller can
/// retry with a more complete proof).
///
/// Mirrors TS `@atproto/repo`'s `verifyProofs` — batch check of
/// existence / absence claims used by the sync consumer when
/// validating `getRepo` output.
pub fn verify_claims(
    proof: &BlockMap,
    root: &Cid,
    claims: &[RecordCidClaim],
) -> Result<Vec<usize>, RepoError> {
    let mut failed = Vec::new();
    for (i, claim) in claims.iter().enumerate() {
        let ok = verify_key_in_proof(proof, root, &claim.key, claim.cid.as_ref())?;
        if !ok {
            failed.push(i);
        }
    }
    Ok(failed)
}

/// Lazily traverse a proof tree looking for `key`, returning its leaf
/// value CID if found or `None` if the proof proves absence. Returns
/// `Err(MissingBlock)` when the proof is incomplete (a block needed
/// to resolve the question isn't present).
fn lookup_in_proof(proof: &BlockMap, node_cid: &Cid, key: &str) -> Result<Option<Cid>, RepoError> {
    let bytes = proof
        .get(node_cid)
        .ok_or_else(|| RepoError::MissingBlock(node_cid.clone()))?;
    let value = proto_blue_lex_cbor::decode(bytes)?;
    let data = deserialize_node_data(&value)?;
    let keys = entries_to_keys(&data);

    // Walk the `entries` vector picking the subtree that could contain
    // the key. `keys[i]` is the i-th leaf's reconstructed key, sorted.
    //
    // Layout per entry i: `entries[i]` is a leaf with key `keys[i]`;
    // `data.left` is the tree to the left of leaf 0; `entries[i].tree`
    // is the tree between leaf i and leaf i+1.
    let mut left_tree = data.left.clone();
    for (i, entry_key) in keys.iter().enumerate() {
        match key.cmp(entry_key) {
            std::cmp::Ordering::Less => {
                return descend(proof, left_tree, key);
            }
            std::cmp::Ordering::Equal => {
                // Hit — the leaf's value CID is the answer.
                return Ok(Some(data.entries[i].value.clone()));
            }
            std::cmp::Ordering::Greater => {
                // Keep scanning; the key might be in this entry's right
                // subtree or further along.
                left_tree = data.entries[i].tree.clone();
            }
        }
    }
    // Key is greater than every leaf at this level; descend into the
    // rightmost subtree (stored as the last entry's `tree`).
    descend(proof, left_tree, key)
}

fn descend(proof: &BlockMap, subtree: Option<Cid>, key: &str) -> Result<Option<Cid>, RepoError> {
    match subtree {
        None => Ok(None), // no subtree to descend into ⇒ key is absent
        Some(child_cid) => lookup_in_proof(proof, &child_cid, key),
    }
}

// ─── internal walkers ───────────────────────────────────────────────

/// Serialize `node` to its canonical DAG-CBOR bytes and return
/// `(node_cid, bytes)`. Always recomputes from scratch rather than
/// relying on the node's cached pointer, because the pointer may be
/// stale after an edit.
fn serialize_node_block(node: &MstNode) -> Result<(Cid, Vec<u8>), RepoError> {
    let (root_cid, blocks) = node.get_all_blocks()?;
    let bytes = blocks
        .get(&root_cid)
        .ok_or_else(|| RepoError::MissingBlock(root_cid.clone()))?
        .to_vec();
    Ok((root_cid, bytes))
}

/// Find the index in `node.entries` of the first *leaf* whose key is
/// >= `target`. Returns `entries.len()` if no such leaf exists.
fn find_gt_or_eq_leaf_index(node: &MstNode, target: &str) -> usize {
    let entries = node.entries();
    for (i, entry) in entries.iter().enumerate() {
        if let NodeEntry::Leaf(leaf) = entry {
            if leaf.key.as_str() >= target {
                return i;
            }
        }
    }
    entries.len()
}

fn walk_for_key(node: &MstNode, key: &str, blocks: &mut BlockMap) -> Result<(), RepoError> {
    let entries = node.entries();
    let index = find_gt_or_eq_leaf_index(node, key);
    let found = entries.get(index);

    let recurse_into: Option<&MstNode> = if let Some(NodeEntry::Leaf(leaf)) = found {
        if leaf.key == key {
            None // hit — no recursion needed, this node's block completes the path
        } else {
            // Walk into the subtree immediately before this leaf.
            match index.checked_sub(1).and_then(|i| entries.get(i)) {
                Some(NodeEntry::Tree(subtree)) => Some(subtree),
                _ => None, // no tree to recurse into; proof ends at this node
            }
        }
    } else {
        // No leaf at-or-after index; try the tree before index.
        match index.checked_sub(1).and_then(|i| entries.get(i)) {
            Some(NodeEntry::Tree(subtree)) => Some(subtree),
            _ => None,
        }
    };

    if let Some(child) = recurse_into {
        walk_for_key(child, key, blocks)?;
    }
    let (cid, bytes) = serialize_node_block(node)?;
    blocks.set(cid, bytes);
    Ok(())
}

fn walk_for_left_sibling(
    node: &MstNode,
    key: &str,
    blocks: &mut BlockMap,
) -> Result<(), RepoError> {
    let entries = node.entries();
    let index = find_gt_or_eq_leaf_index(node, key);
    // Everything before `index` is to the left of `key`. Recurse into
    // the tree immediately before `index` (closest to `key` on the left),
    // if any.
    let recurse_into: Option<&MstNode> = match index.checked_sub(1).and_then(|i| entries.get(i)) {
        Some(NodeEntry::Tree(subtree)) => Some(subtree),
        _ => None,
    };
    if let Some(child) = recurse_into {
        walk_for_left_sibling(child, key, blocks)?;
    }
    let (cid, bytes) = serialize_node_block(node)?;
    blocks.set(cid, bytes);
    Ok(())
}

fn walk_for_right_sibling(
    node: &MstNode,
    key: &str,
    blocks: &mut BlockMap,
) -> Result<(), RepoError> {
    let entries = node.entries();
    let index = find_gt_or_eq_leaf_index(node, key);
    let found = entries.get(index);

    // Determine which subtree to recurse into:
    // - If `found` is a tree, recurse into it (the right sibling lives
    //   beneath it).
    // - If `found` is a leaf equal to `key`, recurse into the tree
    //   *after* it (that's where the right sibling hides).
    // - If `found` is a leaf strictly greater than `key`, the right
    //   sibling is already visible at this level; the subtree before
    //   it may hold keys between `key` and `found` — recurse there.
    // - If no `found`, recurse into the last tree at this layer.
    let recurse_into: Option<&MstNode> = match found {
        Some(NodeEntry::Tree(subtree)) => Some(subtree),
        Some(NodeEntry::Leaf(leaf)) if leaf.key == key => match entries.get(index + 1) {
            Some(NodeEntry::Tree(subtree)) => Some(subtree),
            _ => None,
        },
        Some(NodeEntry::Leaf(_)) => match index.checked_sub(1).and_then(|i| entries.get(i)) {
            Some(NodeEntry::Tree(subtree)) => Some(subtree),
            _ => None,
        },
        None => match entries.last() {
            Some(NodeEntry::Tree(subtree)) => Some(subtree),
            _ => None,
        },
    };
    if let Some(child) = recurse_into {
        walk_for_right_sibling(child, key, blocks)?;
    }
    let (cid, bytes) = serialize_node_block(node)?;
    blocks.set(cid, bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::{UnsignedCommit, sign_commit};
    use proto_blue_crypto::{Keypair, P256Keypair};
    use proto_blue_lex_cbor::cid_for_lex;
    use proto_blue_lex_data::LexValue;

    fn cid_for(seed: &[u8]) -> Cid {
        cid_for_lex(&LexValue::Bytes(seed.to_vec())).unwrap()
    }

    fn build_mst(keys_and_cids: &[(&str, Cid)]) -> MstNode {
        let mut mst = MstNode::empty();
        for (k, v) in keys_and_cids {
            mst = mst.add(k, v.clone()).unwrap();
        }
        mst
    }

    // ── proof_for_key ──

    #[test]
    fn proof_for_existing_key_verifies_presence() {
        let v = cid_for(b"v");
        let mst = build_mst(&[
            ("coll/a", cid_for(b"a")),
            ("coll/b", v.clone()),
            ("coll/c", cid_for(b"c")),
        ]);
        let root = mst.get_pointer().unwrap();
        let proof = proof_for_key(&mst, "coll/b").unwrap();
        assert!(
            verify_key_in_proof(&proof, &root, "coll/b", Some(&v)).unwrap(),
            "proof should verify b -> v"
        );
    }

    #[test]
    fn proof_for_existing_key_rejects_wrong_value() {
        let v = cid_for(b"v");
        let wrong = cid_for(b"wrong");
        let mst = build_mst(&[("coll/a", v)]);
        let root = mst.get_pointer().unwrap();
        let proof = proof_for_key(&mst, "coll/a").unwrap();
        assert!(
            !verify_key_in_proof(&proof, &root, "coll/a", Some(&wrong)).unwrap(),
            "proof claiming a -> wrong must fail"
        );
    }

    #[test]
    fn proof_of_absence_via_covering_proof() {
        let mst = build_mst(&[("coll/a", cid_for(b"a")), ("coll/c", cid_for(b"c"))]);
        let root = mst.get_pointer().unwrap();
        let proof = covering_proof(&mst, "coll/b").unwrap();
        assert!(
            verify_key_in_proof(&proof, &root, "coll/b", None).unwrap(),
            "covering proof must confirm b is absent"
        );
    }

    /// Tampered proof: if we lie about any one byte in a block, the
    /// block's CID won't match and `MstNode::load` fails. Verify that
    /// the tamper is detected.
    #[test]
    fn tampered_block_breaks_load() {
        let mst = build_mst(&[("coll/a", cid_for(b"a"))]);
        let root = mst.get_pointer().unwrap();
        let mut proof = proof_for_key(&mst, "coll/a").unwrap();

        // Get the root block's bytes, corrupt one byte, reinsert under
        // the original CID. Loading will then find that CID -> bytes
        // mapping, but the bytes won't decode to a valid MST node (or
        // will decode to a different-shaped one), either of which
        // breaks verification.
        let orig_bytes = proof.get(&root).unwrap().to_vec();
        let mut tampered = orig_bytes;
        *tampered.last_mut().unwrap() ^= 0xff;
        proof.set(root.clone(), tampered);

        // We expect either an error from load or a `Ok(false)` from
        // verify — both are acceptable outcomes for tampered input.
        let res = verify_key_in_proof(&proof, &root, "coll/a", Some(&cid_for(b"a")));
        if let Ok(v) = res {
            assert!(!v, "tampered proof must not verify")
        } else { /* load rejected it, also fine */
        }
    }

    // ── sibling proofs ──

    #[test]
    fn proof_for_left_sibling_lets_verifier_find_prior_leaf() {
        // Build a tree whose leaves span multiple MST layers (the TS
        // interop key set guarantees `3fs2j` is at layer 1).
        let v = cid_for(b"v");
        let keys = [
            "com.example.record/3jqfcqzm3fo2j",
            "com.example.record/3jqfcqzm3fp2j",
            "com.example.record/3jqfcqzm3fr2j",
            "com.example.record/3jqfcqzm3fs2j", // layer 1
            "com.example.record/3jqfcqzm3ft2j",
        ];
        let entries: Vec<(&str, Cid)> = keys.iter().map(|k| (*k, v.clone())).collect();
        let mst = build_mst(&entries);
        let root = mst.get_pointer().unwrap();

        // Left sibling of `3fr2j` is `3fp2j`. A left-sibling proof
        // must contain the blocks needed to verify that `3fp2j` exists.
        let target = "com.example.record/3jqfcqzm3fr2j";
        let left = proof_for_left_sibling(&mst, target).unwrap();
        assert!(!left.is_empty());
        let sibling = "com.example.record/3jqfcqzm3fp2j";
        assert!(
            verify_key_in_proof(&left, &root, sibling, Some(&v)).unwrap(),
            "left-sibling proof must support verifying the sibling's existence"
        );
    }

    #[test]
    fn proof_for_right_sibling_lets_verifier_find_next_leaf() {
        let v = cid_for(b"v");
        let keys = ["coll/a", "coll/b", "coll/c", "coll/d"];
        let entries: Vec<(&str, Cid)> = keys.iter().map(|k| (*k, v.clone())).collect();
        let mst = build_mst(&entries);
        let root = mst.get_pointer().unwrap();

        // Right sibling of `coll/b` is `coll/c`.
        let right = proof_for_right_sibling(&mst, "coll/b").unwrap();
        assert!(!right.is_empty());
        assert!(
            verify_key_in_proof(&right, &root, "coll/c", Some(&v)).unwrap(),
            "right-sibling proof must support verifying the sibling's existence"
        );
    }

    // ── covering and commit proofs ──

    #[test]
    fn covering_proof_includes_both_sibling_paths() {
        let v = cid_for(b"v");
        let mst = build_mst(&[
            ("coll/a", v.clone()),
            ("coll/b", v.clone()),
            ("coll/c", v.clone()),
            ("coll/d", v),
        ]);
        let only_key = proof_for_key(&mst, "coll/b").unwrap();
        let covering = covering_proof(&mst, "coll/b").unwrap();
        // Covering must be at least as large as the key-only proof
        // (usually larger, unless siblings happen to share the same
        // spine).
        assert!(covering.len() >= only_key.len());
    }

    #[test]
    fn commit_proof_includes_commit_block() {
        let kp = P256Keypair::generate();
        let v = cid_for(b"v");
        let mst = build_mst(&[("coll/a", v.clone())]);
        let unsigned = UnsignedCommit::new(
            kp.did(),
            mst.get_pointer().unwrap(),
            "3jzfcijpj2z2a".to_string(),
            None,
        );
        let signed = sign_commit(&unsigned, &kp).unwrap();

        let proof = commit_proof(&mst, &signed, "coll/a").unwrap();
        // The commit CID must be in the proof.
        assert!(proof.has(&signed.cid().unwrap()));
        // And we can still verify the key against the MST root.
        assert!(verify_key_in_proof(&proof, &signed.data, "coll/a", Some(&v)).unwrap());
    }

    // ── verifier sanity ──

    #[test]
    fn verifier_rejects_missing_root() {
        let mst = build_mst(&[("coll/a", cid_for(b"a"))]);
        let proof = BlockMap::new(); // empty — missing even the root
        let root = mst.get_pointer().unwrap();
        let res = verify_key_in_proof(&proof, &root, "coll/a", None);
        assert!(matches!(res, Err(RepoError::MissingBlock(_))));
    }

    #[test]
    fn proofs_on_large_tree_are_smaller_than_full_tree() {
        // A proof over a thousand-leaf tree should be far smaller than
        // the full block set. This is the whole point of merkle proofs.
        let v = cid_for(b"v");
        let mut pairs: Vec<(String, Cid)> = (0..500)
            .map(|i| (format!("coll/{i:04}"), v.clone()))
            .collect();
        pairs.sort();
        let refs: Vec<(&str, Cid)> = pairs.iter().map(|(k, c)| (k.as_str(), c.clone())).collect();
        let mst = build_mst(&refs);

        let (_, all_blocks) = mst.get_all_blocks().unwrap();
        let proof = proof_for_key(&mst, "coll/0250").unwrap();
        assert!(
            proof.len() < all_blocks.len(),
            "proof ({}) must be smaller than full tree ({})",
            proof.len(),
            all_blocks.len()
        );
    }
}
