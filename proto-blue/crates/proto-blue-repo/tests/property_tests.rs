#![allow(clippy::pedantic, clippy::nursery)]

//! Property-based tests for repository data structures.

use proptest::prelude::*;
use std::collections::BTreeMap;

use proto_blue_lex_data::{Cid, LexValue};
use proto_blue_repo::{
    BlockMap, MstNode, RepoError, covering_proof, proof_for_key, proof_for_left_sibling,
    proof_for_right_sibling, verify_key_in_proof,
};

// --- MST property tests ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn mst_insert_order_independent(
        entries in proptest::collection::vec(
            ("[a-z]{1,5}/[a-z0-9]{5,15}", "[a-z]{1,20}"),
            1..30
        )
    ) {
        // Deduplicate keys
        let mut unique: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in &entries {
            unique.insert(k.clone(), v.clone());
        }
        let entries: Vec<(String, String)> = unique.into_iter().collect();

        if entries.is_empty() {
            return Ok(());
        }

        // Insert in forward order
        let mut mst1 = MstNode::empty();
        for (k, v) in &entries {
            let val = LexValue::String(v.clone());
            let cid = proto_blue_lex_cbor::cid_for_lex(&val).unwrap();
            mst1 = mst1.add(k, cid).unwrap();
        }

        // Insert in reverse order
        let mut mst2 = MstNode::empty();
        for (k, v) in entries.iter().rev() {
            let val = LexValue::String(v.clone());
            let cid = proto_blue_lex_cbor::cid_for_lex(&val).unwrap();
            mst2 = mst2.add(k, cid).unwrap();
        }

        // Both trees should produce the same leaves
        let leaves1 = mst1.leaves();
        let leaves2 = mst2.leaves();
        prop_assert_eq!(leaves1.len(), leaves2.len(), "Trees should have same number of entries");
        for (a, b) in leaves1.iter().zip(leaves2.iter()) {
            prop_assert_eq!(&a.key, &b.key, "Keys should match");
            prop_assert_eq!(a.value.to_string_base32(), b.value.to_string_base32(), "CIDs should match");
        }

        // Both should produce the same root CID
        let (cid1, _) = mst1.get_all_blocks().unwrap();
        let (cid2, _) = mst2.get_all_blocks().unwrap();
        prop_assert_eq!(cid1.to_string_base32(), cid2.to_string_base32());
    }

    #[test]
    fn mst_insert_then_delete_returns_to_empty(
        keys in proptest::collection::vec("[a-z]{1,5}/[a-z0-9]{5,15}", 1..20)
    ) {
        let unique_keys: Vec<String> = keys.into_iter().collect::<std::collections::BTreeSet<_>>().into_iter().collect();

        let val = LexValue::String("value".into());
        let cid = proto_blue_lex_cbor::cid_for_lex(&val).unwrap();

        let mut mst = MstNode::empty();
        for k in &unique_keys {
            mst = mst.add(k, cid.clone()).unwrap();
        }
        prop_assert_eq!(mst.leaves().len(), unique_keys.len());

        // Delete all
        for k in &unique_keys {
            mst = mst.delete(k).unwrap();
        }
        prop_assert_eq!(mst.leaves().len(), 0, "Tree should be empty after deleting all keys");
    }

    #[test]
    fn mst_list_is_sorted(
        entries in proptest::collection::vec(
            ("[a-z]{1,5}/[a-z0-9]{5,15}", any::<u64>()),
            1..30
        )
    ) {
        let mut mst = MstNode::empty();
        for (k, v) in &entries {
            let val = LexValue::Integer(*v as i64);
            let cid = proto_blue_lex_cbor::cid_for_lex(&val).unwrap();
            // Ignore duplicate key errors
            if let Ok(new_mst) = mst.add(k, cid) {
                mst = new_mst;
            }
        }
        let leaves = mst.leaves();
        for window in leaves.windows(2) {
            prop_assert!(window[0].key < window[1].key, "Leaves must be sorted: {} < {}", window[0].key, window[1].key);
        }
    }
}

// --- CAR roundtrip ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn car_roundtrip_preserves_blocks(
        blocks in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 1..100),
            1..10
        )
    ) {
        let mut block_map = proto_blue_repo::BlockMap::new();
        for data in &blocks {
            let val = LexValue::Bytes(data.clone());
            let cid = proto_blue_lex_cbor::cid_for_lex(&val).unwrap();
            let encoded = proto_blue_lex_cbor::encode(&val).unwrap();
            block_map.set(cid, encoded);
        }

        // Use the first CID as root
        let all_cids = block_map.cids();
        let first_cid = &all_cids[0];
        let car_bytes = proto_blue_repo::blocks_to_car(Some(first_cid), &block_map).unwrap();

        let (roots, restored) = proto_blue_repo::read_car(&car_bytes).unwrap();
        prop_assert_eq!(roots.len(), 1);
        prop_assert_eq!(roots[0].to_string_base32(), first_cid.to_string_base32());
        prop_assert_eq!(restored.len(), block_map.len());
    }
}

// --- BlockMap / CidSet property tests ---

proptest! {
    #[test]
    fn blockmap_set_get_roundtrip(
        entries in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 1..50),
            1..20
        )
    ) {
        let mut bm = proto_blue_repo::BlockMap::new();
        let mut cids = Vec::new();
        for data in &entries {
            let val = LexValue::Bytes(data.clone());
            let cid = proto_blue_lex_cbor::cid_for_lex(&val).unwrap();
            let encoded = proto_blue_lex_cbor::encode(&val).unwrap();
            bm.set(cid.clone(), encoded.clone());
            cids.push((cid, encoded));
        }

        for (cid, expected_data) in &cids {
            let retrieved = bm.get(cid).unwrap();
            prop_assert_eq!(retrieved, expected_data.as_slice());
        }
    }

    #[test]
    fn cidset_add_has_consistency(
        data_items in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 1..50),
            1..20
        )
    ) {
        let mut set = proto_blue_repo::CidSet::new();
        let mut cids = Vec::new();
        for data in &data_items {
            let val = LexValue::Bytes(data.clone());
            let cid = proto_blue_lex_cbor::cid_for_lex(&val).unwrap();
            set.add(cid.clone());
            cids.push(cid);
        }
        for cid in &cids {
            prop_assert!(set.has(cid), "CidSet should contain all added CIDs");
        }
    }
}

// ─── proof pipeline properties ──────────────────────────────────────
//
// External review (jacquard author) flagged the absence of property /
// fuzz coverage for proofs as the highest-leverage gap. The TS reference
// PDS has been observed emitting sync v1.1 commits whose `blocks` field
// is missing required proof blocks; the verifier must reject such input
// rather than silently accept it.
//
// These properties pin the verifier's contract: soundness, completeness,
// adversarial robustness against block deletion and byte-level tamper,
// and the strict-superset invariant that motivates tranquil-pds's
// "slightly overestimate" emission strategy.

/// Build an MST from a deduped `(key, cid)` set, returning the MST and a
/// `(key, value_cid)` map so tests can ask "what's the actual value of
/// this key?". The set is preserved insertion-deterministically so trees
/// produced by the same input always have the same root CID.
fn build_mst_with_index(entries: &[(String, u64)]) -> (MstNode, BTreeMap<String, Cid>) {
    let mut mst = MstNode::empty();
    let mut index: BTreeMap<String, Cid> = BTreeMap::new();
    for (key, salt) in entries {
        // Unique value-CID per key so wrong-value tests have something
        // to compare against. `cid_for_lex(LexValue::Integer(salt))`
        // produces a deterministic CID.
        let val = LexValue::Integer(*salt as i64);
        let cid = proto_blue_lex_cbor::cid_for_lex(&val).unwrap();
        if let Ok(new) = mst.add(key, cid.clone()) {
            mst = new;
            index.insert(key.clone(), cid);
        }
    }
    (mst, index)
}

fn arb_entries(min: usize, max: usize) -> impl Strategy<Value = Vec<(String, u64)>> {
    proptest::collection::vec(("[a-z]{1,8}/[a-z0-9]{4,12}", any::<u64>()), min..max)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(40))]

    /// Soundness: a covering_proof for a present key must verify the key's
    /// actual value.
    #[test]
    fn proof_verifies_present_key(entries in arb_entries(1, 20)) {
        let (mst, index) = build_mst_with_index(&entries);
        prop_assume!(!index.is_empty());
        let root = mst.get_pointer().unwrap();
        for (key, expected) in &index {
            let proof = covering_proof(&mst, key).unwrap();
            let ok = verify_key_in_proof(&proof, &root, key, Some(expected)).unwrap();
            prop_assert!(ok, "covering_proof must verify actual value for present key {key}");
        }
    }

    /// Completeness: claiming a wrong value for a present key must NOT
    /// verify. A passing verifier here would mean the proof is forgeable.
    #[test]
    fn proof_rejects_wrong_value(entries in arb_entries(1, 20)) {
        let (mst, index) = build_mst_with_index(&entries);
        prop_assume!(!index.is_empty());
        let wrong_cid = proto_blue_lex_cbor::cid_for_lex(
            &LexValue::String("definitely-not-the-real-value".into())
        ).unwrap();
        let root = mst.get_pointer().unwrap();
        for (key, actual) in &index {
            // Skip if by astronomical accident the wrong cid equals the actual.
            if actual.to_string_base32() == wrong_cid.to_string_base32() {
                continue;
            }
            let proof = covering_proof(&mst, key).unwrap();
            let ok = verify_key_in_proof(&proof, &root, key, Some(&wrong_cid)).unwrap();
            prop_assert!(!ok, "wrong-value claim must be rejected for key {key}");
        }
    }

    /// Absence: a covering_proof for a key not in the tree must verify
    /// the absence claim (`expected == None`).
    #[test]
    fn proof_verifies_absence_for_missing_key(
        entries in arb_entries(1, 20),
        absent_key in "[a-z]{1,8}/[a-z0-9]{4,12}",
    ) {
        let (mst, index) = build_mst_with_index(&entries);
        prop_assume!(!index.contains_key(&absent_key));
        let root = mst.get_pointer().unwrap();
        let proof = covering_proof(&mst, &absent_key).unwrap();
        let ok = verify_key_in_proof(&proof, &root, &absent_key, None).unwrap();
        prop_assert!(ok, "covering_proof must verify absence of {absent_key}");
    }

    /// Adversarial robustness #1: removing any single block from a valid
    /// proof must NEVER produce `Ok(false)` (a silent accept of a wrong
    /// claim). Acceptable outcomes are `Ok(true)` (the block was
    /// redundant — proof contained slack) or `Err(MissingBlock)` (the
    /// verifier correctly identified a structural gap).
    ///
    /// This is the core invariant motivating tranquil-pds's slight
    /// overestimate: if a PDS emits a proof and a single block is
    /// missing in transit, a strict verifier returns MissingBlock and
    /// the consumer can re-fetch. A loose verifier silently accepts a
    /// false claim — the bug fig observed in the reference PDS.
    #[test]
    fn block_removal_never_produces_silent_false_accept(
        entries in arb_entries(2, 12),
    ) {
        let (mst, index) = build_mst_with_index(&entries);
        prop_assume!(!index.is_empty());
        let root = mst.get_pointer().unwrap();
        let key = index.keys().next().unwrap().clone();
        let expected = index.get(&key).unwrap().clone();
        let proof = covering_proof(&mst, &key).unwrap();

        let cids: Vec<Cid> = proof.iter().map(|(c, _)| c.clone()).collect();
        for cid_to_remove in cids {
            let mut shrunk = BlockMap::new();
            for (c, b) in proof.iter() {
                if c != &cid_to_remove {
                    shrunk.set(c.clone(), b.to_vec());
                }
            }
            match verify_key_in_proof(&shrunk, &root, &key, Some(&expected)) {
                Ok(true) => { /* block was redundant — fine */ }
                Err(RepoError::MissingBlock(_)) => { /* structural gap — fine */ }
                other => {
                    prop_assert!(
                        false,
                        "removing block {} produced {:?} for present key {key}; \
                         a missing block must NEVER cause Ok(false)",
                        cid_to_remove.to_string_base32(),
                        other,
                    );
                }
            }
        }
    }

    /// Adversarial robustness #2: adding unrelated blocks to a valid
    /// proof must not change the verdict. The verifier consults blocks
    /// it needs and should ignore noise.
    #[test]
    fn extra_blocks_do_not_change_verdict(
        entries in arb_entries(1, 12),
        garbage in proptest::collection::vec(any::<u64>(), 1..6),
    ) {
        let (mst, index) = build_mst_with_index(&entries);
        prop_assume!(!index.is_empty());
        let root = mst.get_pointer().unwrap();
        let key = index.keys().next().unwrap().clone();
        let expected = index.get(&key).unwrap().clone();
        let baseline = covering_proof(&mst, &key).unwrap();
        let baseline_ok = verify_key_in_proof(&baseline, &root, &key, Some(&expected)).unwrap();

        // Build a polluted proof by adding random unrelated blocks.
        let mut polluted = BlockMap::new();
        for (c, b) in baseline.iter() {
            polluted.set(c.clone(), b.to_vec());
        }
        for salt in &garbage {
            let val = LexValue::Integer(*salt as i64);
            let bytes = proto_blue_lex_cbor::encode(&val).unwrap();
            let cid = proto_blue_lex_cbor::cid_for_lex(&val).unwrap();
            polluted.set(cid, bytes);
        }
        let polluted_ok = verify_key_in_proof(&polluted, &root, &key, Some(&expected)).unwrap();
        prop_assert_eq!(
            baseline_ok, polluted_ok,
            "verdict must be invariant under unrelated extra blocks"
        );
    }

    /// Adversarial robustness #3 (forgery resistance): no combination of
    /// byte-tamper plus a wrong-value claim can produce a silent
    /// `Ok(true)` accept. This is the actual security property: the
    /// verifier's contract is that pre-validated content-addressed
    /// blocks are trusted, but it must NEVER attest to a claim the tree
    /// doesn't support, regardless of how the proof bytes are mangled.
    ///
    /// Note on what this is NOT testing: a tamper that doesn't affect
    /// the queried key's lookup path is allowed to leave `Ok(true)` for
    /// the *true* original claim — that's not a forgery, just an
    /// internal-consistency observation. CID-layer tamper detection
    /// belongs upstream (CAR reader, `MstNode::load`).
    #[test]
    fn tamper_cannot_force_wrong_value_acceptance(entries in arb_entries(1, 8)) {
        let (mst, index) = build_mst_with_index(&entries);
        prop_assume!(!index.is_empty());
        let root = mst.get_pointer().unwrap();
        let key = index.keys().next().unwrap().clone();
        let actual = index.get(&key).unwrap().clone();
        let wrong_cid = proto_blue_lex_cbor::cid_for_lex(
            &LexValue::String("forged-value-claim".into())
        ).unwrap();
        // Skip the cosmically-unlucky case where the wrong CID happens to equal the actual.
        prop_assume!(actual.to_string_base32() != wrong_cid.to_string_base32());

        let proof = covering_proof(&mst, &key).unwrap();
        let cids: Vec<Cid> = proof.iter().map(|(c, _)| c.clone()).collect();
        for cid in cids {
            let bytes = proof.get(&cid).unwrap().to_vec();
            if bytes.is_empty() {
                continue;
            }
            let mut tampered_bytes = bytes;
            *tampered_bytes.last_mut().unwrap() ^= 0xff;

            let mut tampered = BlockMap::new();
            for (c, b) in proof.iter() {
                if c == &cid {
                    tampered.set(c.clone(), tampered_bytes.clone());
                } else {
                    tampered.set(c.clone(), b.to_vec());
                }
            }

            // The wrong-value claim must NEVER come back true, regardless of tamper.
            match verify_key_in_proof(&tampered, &root, &key, Some(&wrong_cid)) {
                Ok(false) | Err(_) => { /* correct rejection */ }
                Ok(true) => {
                    prop_assert!(
                        false,
                        "tampered block {} produced Ok(true) for forged value — \
                         wrong-value forgery accepted",
                        cid.to_string_base32(),
                    );
                }
            }
        }
    }

    /// Strict-superset structural invariant: covering_proof must contain
    /// the union of proof_for_key, proof_for_left_sibling, and
    /// proof_for_right_sibling. The implementation defines covering_proof
    /// as that union, so this is a regression test guarding against future
    /// "optimization" that drops blocks from one of the three.
    ///
    /// This is the property that makes tranquil-pds's slight overestimate
    /// the right shape: covering_proof is already a strict superset of
    /// any single-direction proof, so emitters can use it confidently.
    #[test]
    fn covering_proof_is_superset_of_each_directional_proof(entries in arb_entries(2, 15)) {
        let (mst, index) = build_mst_with_index(&entries);
        prop_assume!(!index.is_empty());
        let key = index.keys().next().unwrap().clone();

        let key_proof = proof_for_key(&mst, &key).unwrap();
        let left_proof = proof_for_left_sibling(&mst, &key).unwrap();
        let right_proof = proof_for_right_sibling(&mst, &key).unwrap();
        let covering = covering_proof(&mst, &key).unwrap();

        for (cid, _) in key_proof.iter() {
            prop_assert!(
                covering.has(cid),
                "covering_proof missing block from proof_for_key: {}",
                cid.to_string_base32(),
            );
        }
        for (cid, _) in left_proof.iter() {
            prop_assert!(
                covering.has(cid),
                "covering_proof missing block from proof_for_left_sibling: {}",
                cid.to_string_base32(),
            );
        }
        for (cid, _) in right_proof.iter() {
            prop_assert!(
                covering.has(cid),
                "covering_proof missing block from proof_for_right_sibling: {}",
                cid.to_string_base32(),
            );
        }
    }
}
