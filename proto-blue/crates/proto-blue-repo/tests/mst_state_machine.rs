#![allow(clippy::pedantic, clippy::nursery)]

//! State-machine property test for [`MstNode`] mutations.
//!
//! Generates random sequences of `add` / `update` / `delete` calls
//! against a small key pool and, after every step, asserts:
//!
//! - `mst.get(k)` matches a reference `BTreeMap<String, Cid>` oracle
//!   for every key ever touched (and for a few untouched keys that
//!   must continue to return `None`).
//! - `mst.leaves()` as a set equals the oracle's entries.
//! - `mst.entries()` stays internally consistent (layer counts,
//!   pointer chains) by reloading via `get_all_blocks` → `load` and
//!   confirming the reloaded tree's leaves equal the original.
//!
//! Flat proptests (`proto-blue-repo/tests/property_tests.rs`) check
//! single-shot invariants; this file is about sequences, where MST
//! bugs actually hide (nodes mis-split on boundary-depth keys,
//! `update(missing_key)` changing semantics, etc.).

use std::collections::BTreeMap;

use proptest::prelude::*;
use proto_blue_lex_data::Cid;
use proto_blue_repo::mst::MstNode;

/// One operation in a generated test sequence.
#[derive(Debug, Clone)]
enum Op {
    /// Insert or no-op if the key already exists with this value.
    Add(String),
    /// Change the CID for an existing key; no-op (error) if absent.
    Update(String),
    /// Delete a key; no-op (error) if absent.
    Delete(String),
}

/// Small fixed pool of valid MST keys. Using a bounded set forces
/// the generated sequences to collide (update-after-delete, add-
/// already-present, etc.) instead of wandering through unique keys.
fn key_pool() -> Vec<String> {
    vec![
        "app.bsky.feed.post/aaa".into(),
        "app.bsky.feed.post/bbb".into(),
        "app.bsky.feed.post/ccc".into(),
        "app.bsky.feed.like/aaa".into(),
        "app.bsky.feed.like/zzz".into(),
        "app.bsky.graph.follow/aaa".into(),
        "app.bsky.graph.follow/bbb".into(),
        "app.bsky.actor.profile/self".into(),
    ]
}

/// Generate one of the three ops keyed against the small pool.
fn arb_op() -> impl Strategy<Value = Op> {
    let keys = key_pool();
    let key_strat = proptest::sample::select(keys);
    prop_oneof![
        key_strat.clone().prop_map(Op::Add),
        key_strat.clone().prop_map(Op::Update),
        key_strat.prop_map(Op::Delete),
    ]
}

/// Synthesize a deterministic CID for a test counter. Keeps each
/// generated value unique so `update` changes something observable.
fn make_cid(n: u32) -> Cid {
    // SHA-256 of the little-endian bytes of `n` → stable, deterministic,
    // distinct across values.
    Cid::for_raw(&n.to_le_bytes())
}

proptest! {
    #![proptest_config(ProptestConfig {
        // 64 sequences of up to 40 ops apiece is plenty to shake out
        // the common interleaving bugs without blowing the `cargo
        // test` budget.
        cases: 64,
        .. ProptestConfig::default()
    })]

    #[test]
    fn mst_matches_oracle_across_arbitrary_op_sequences(
        ops in proptest::collection::vec(arb_op(), 1..40),
    ) {
        // Reference oracle: the "intended" state, always correct.
        let mut oracle: BTreeMap<String, Cid> = BTreeMap::new();
        // System under test.
        let mut mst = MstNode::from_entries(vec![]);
        let mut value_counter: u32 = 0;

        for op in ops {
            match op {
                Op::Add(key) => {
                    value_counter += 1;
                    let cid = make_cid(value_counter);
                    // MST refuses duplicate-key inserts; the oracle
                    // tracks that by only recording the add on first
                    // sight.
                    match mst.add(&key, cid.clone()) {
                        Ok(next) => {
                            prop_assert!(
                                !oracle.contains_key(&key),
                                "MST accepted add of existing key {key}"
                            );
                            mst = next;
                            oracle.insert(key, cid);
                        }
                        Err(_) => {
                            prop_assert!(
                                oracle.contains_key(&key),
                                "MST rejected add of new key {key}"
                            );
                        }
                    }
                }
                Op::Update(key) => {
                    value_counter += 1;
                    let cid = make_cid(value_counter);
                    match mst.update(&key, cid.clone()) {
                        Ok(next) => {
                            prop_assert!(
                                oracle.contains_key(&key),
                                "MST updated missing key {key}"
                            );
                            mst = next;
                            oracle.insert(key, cid);
                        }
                        Err(_) => {
                            prop_assert!(
                                !oracle.contains_key(&key),
                                "MST rejected update of present key {key}"
                            );
                        }
                    }
                }
                Op::Delete(key) => match mst.delete(&key) {
                    Ok(next) => {
                        prop_assert!(
                            oracle.contains_key(&key),
                            "MST deleted missing key {key}"
                        );
                        mst = next;
                        oracle.remove(&key);
                    }
                    Err(_) => {
                        prop_assert!(
                            !oracle.contains_key(&key),
                            "MST rejected delete of present key {key}"
                        );
                    }
                },
            }

            // Per-step invariants.
            //
            // 1. Every oracle entry is reachable in the tree and maps
            //    to the same CID.
            for (k, v) in &oracle {
                let got = mst.get(k);
                prop_assert_eq!(
                    got.as_ref(),
                    Some(v),
                    "mst.get({}) = {:?}, oracle says {}",
                    k,
                    got,
                    v
                );
            }

            // 2. `leaves()` enumerates exactly the oracle entries.
            let mut leaves: BTreeMap<String, Cid> = BTreeMap::new();
            for leaf in mst.leaves() {
                prop_assert!(
                    leaves.insert(leaf.key.clone(), leaf.value.clone()).is_none(),
                    "duplicate leaf for key {}",
                    leaf.key
                );
            }
            prop_assert_eq!(&leaves, &oracle, "leaves diverged from oracle");

            // 3. Keys never in the oracle must not be present in the
            //    tree. Catches a bug where delete leaves a stub.
            for k in key_pool() {
                if !oracle.contains_key(&k) {
                    prop_assert_eq!(
                        mst.get(&k),
                        None,
                        "mst.get({}) returned Some after delete/no-add",
                        k
                    );
                }
            }
        }

        // End-of-sequence invariant: serialize the full tree to a
        // block map, reload from the root CID, and verify the
        // reloaded tree has identical leaves. Catches round-trip
        // corruption bugs that per-step `get` / `leaves` checks miss.
        let (root_cid, blocks) = mst.get_all_blocks().expect("serialize MST to blocks");
        let reloaded = MstNode::load(&root_cid, &blocks).expect("reload MST from blocks");
        let mut reloaded_leaves: BTreeMap<String, Cid> = BTreeMap::new();
        for leaf in reloaded.leaves() {
            reloaded_leaves.insert(leaf.key.clone(), leaf.value.clone());
        }
        prop_assert_eq!(reloaded_leaves, oracle, "reloaded MST diverged from oracle");
    }
}
