//! Property-based tests for repository data structures.

use proptest::prelude::*;
use std::collections::BTreeMap;

use proto_blue_lex_data::LexValue;
use proto_blue_repo::mst::MstNode;

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
