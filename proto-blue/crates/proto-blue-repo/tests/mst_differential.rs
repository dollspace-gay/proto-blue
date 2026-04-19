//! Differential MST tests against the official TS SDK test suite.
//!
//! Ported from `packages/repo/tests/mst.test.ts` in bluesky-social/atproto.
//! Each test here has a direct counterpart in the TS suite; the Rust MST
//! must produce identical results (leading-zero counts, fanout layers, and
//! root CIDs) or the two implementations will silently diverge on any
//! federated repo sync.

use proto_blue_lex_data::Cid;
use proto_blue_repo::{
    MstNode,
    mst::util::{count_prefix_len, ensure_valid_mst_key, leading_zeros_on_hash},
};

/// The `cid1` value used by the TS MST interop test suite:
/// `bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454`.
fn ts_cid1() -> Cid {
    Cid::from_str_multibase("bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454")
        .expect("valid TS fixture CID")
}

/// Shorthand for the single-CID inserter used across the fixtures.
fn add(mst: MstNode, key: &str) -> MstNode {
    mst.add(key, ts_cid1())
        .unwrap_or_else(|e| panic!("add({key:?}) failed: {e}"))
}

fn root_cid(mst: &MstNode) -> String {
    let (cid, _blocks) = mst.get_all_blocks().expect("get_all_blocks");
    cid.to_string_base32()
}

// -----------------------------------------------------------------------
// Fanout: leading zero count per key must match TS annotations exactly.
// TS comments in mst.test.ts label each key with its layer — these values
// come from SHA-256 and are ground truth.
// -----------------------------------------------------------------------

#[test]
fn leading_zeros_matches_ts_annotations() {
    let cases: &[(&str, usize)] = &[
        // From 'trims top of tree on delete' + 'handles insertion that splits'.
        ("com.example.record/3jqfcqzm3fn2j", 0),
        ("com.example.record/3jqfcqzm3fo2j", 0),
        ("com.example.record/3jqfcqzm3fp2j", 0),
        ("com.example.record/3jqfcqzm3fr2j", 0),
        ("com.example.record/3jqfcqzm3fs2j", 1),
        ("com.example.record/3jqfcqzm3ft2j", 0),
        ("com.example.record/3jqfcqzm3fu2j", 0),
        ("com.example.record/3jqfcqzm3fx2j", 2),
        ("com.example.record/3jqfcqzm3fz2j", 0),
        ("com.example.record/3jqfcqzm4fc2j", 0),
        ("com.example.record/3jqfcqzm4fd2j", 1),
        ("com.example.record/3jqfcqzm4ff2j", 0),
        ("com.example.record/3jqfcqzm4fg2j", 0),
        ("com.example.record/3jqfcqzm4fh2j", 0),
    ];
    let mut mismatches = Vec::new();
    for (key, expected) in cases {
        let got = leading_zeros_on_hash(key);
        if got != *expected {
            mismatches.push(format!("  {key:?}: expected layer {expected}, got {got}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "\nMST layer annotations do not match TS:\n{}",
        mismatches.join("\n")
    );
}

// -----------------------------------------------------------------------
// Known root CIDs: these are burned into the TS test suite as exact
// interop checks. Any divergence here means our tree serialization is
// incompatible with every other atproto implementation.
// -----------------------------------------------------------------------

#[test]
fn empty_tree_root_matches_ts() {
    let mst = MstNode::empty();
    assert_eq!(
        root_cid(&mst),
        "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm",
    );
}

#[test]
fn trivial_tree_root_matches_ts() {
    let mst = add(MstNode::empty(), "com.example.record/3jqfcqzm3fo2j");
    assert_eq!(
        root_cid(&mst),
        "bafyreibj4lsc3aqnrvphp5xmrnfoorvru4wynt6lwidqbm2623a6tatzdu",
    );
}

#[test]
fn singlelayer2_tree_root_matches_ts() {
    let mst = add(MstNode::empty(), "com.example.record/3jqfcqzm3fx2j");
    assert_eq!(mst.get_layer(), 2, "3jqfcqzm3fx2j must be at layer 2");
    assert_eq!(
        root_cid(&mst),
        "bafyreih7wfei65pxzhauoibu3ls7jgmkju4bspy4t2ha2qdjnzqvoy33ai",
    );
}

#[test]
fn simple_tree_root_matches_ts() {
    let mut mst = MstNode::empty();
    for key in [
        "com.example.record/3jqfcqzm3fp2j", // level 0
        "com.example.record/3jqfcqzm3fr2j", // level 0
        "com.example.record/3jqfcqzm3fs2j", // level 1
        "com.example.record/3jqfcqzm3ft2j", // level 0
        "com.example.record/3jqfcqzm4fc2j", // level 0
    ] {
        mst = add(mst, key);
    }
    assert_eq!(
        root_cid(&mst),
        "bafyreicmahysq4n6wfuxo522m6dpiy7z7qzym3dzs756t5n7nfdgccwq7m",
    );
}

// -----------------------------------------------------------------------
// Insertion order independence: any permutation of the same key set must
// yield the same root CID. Covers the `it('is order independent', ...)`
// case from TS.
// -----------------------------------------------------------------------

#[test]
fn root_cid_is_insertion_order_independent() {
    // Two permutations of a 5-key set.
    let keys_a = [
        "com.example.record/3jqfcqzm3fp2j",
        "com.example.record/3jqfcqzm3fr2j",
        "com.example.record/3jqfcqzm3fs2j",
        "com.example.record/3jqfcqzm3ft2j",
        "com.example.record/3jqfcqzm4fc2j",
    ];
    let keys_b = [
        "com.example.record/3jqfcqzm4fc2j",
        "com.example.record/3jqfcqzm3fs2j",
        "com.example.record/3jqfcqzm3fp2j",
        "com.example.record/3jqfcqzm3ft2j",
        "com.example.record/3jqfcqzm3fr2j",
    ];
    let mut a = MstNode::empty();
    for k in keys_a {
        a = add(a, k);
    }
    let mut b = MstNode::empty();
    for k in keys_b {
        b = add(b, k);
    }
    assert_eq!(
        root_cid(&a),
        root_cid(&b),
        "MST root CID must be independent of insertion order"
    );
}

// -----------------------------------------------------------------------
// add-then-delete returns to the prior root.
// -----------------------------------------------------------------------

#[test]
fn add_then_delete_returns_original_root() {
    let base = {
        let mut m = MstNode::empty();
        for k in [
            "com.example.record/3jqfcqzm3fn2j",
            "com.example.record/3jqfcqzm3fo2j",
            "com.example.record/3jqfcqzm3fp2j",
        ] {
            m = add(m, k);
        }
        m
    };
    let base_root = root_cid(&base);
    let with_extra = add(base, "com.example.record/3jqfcqzm3fx2j");
    let after_delete = with_extra
        .delete("com.example.record/3jqfcqzm3fx2j")
        .expect("delete");
    assert_eq!(
        root_cid(&after_delete),
        base_root,
        "add+delete must return to original root CID"
    );
}

// -----------------------------------------------------------------------
// Key validation — matches TS 'MST Interop Allowable Keys'.
// -----------------------------------------------------------------------

#[test]
fn rejects_keys_matching_ts_reject_list() {
    let bad = [
        "",
        "asdf",                   // no collection
        "nested/collection/asdf", // too many slashes
        "coll/",                  // empty rkey
        "/rkey",                  // empty coll
        "coll/jalapeñoA",
        "coll/coöperative",
        "coll/abc💩",
        "coll/key$",
        "coll/key%",
        "coll/key(",
        "coll/key)",
        "coll/key+",
        "coll/key=",
        "coll/@handle",
        "coll/any space",
        "coll/#extra",
        "coll/any+space",
        "coll/number[3]",
        "coll/number(3)",
        "coll/dHJ1ZQ==",
        "coll/\"quote\"",
    ];
    for key in bad {
        assert!(
            ensure_valid_mst_key(key).is_err(),
            "MST key should be rejected: {key:?}"
        );
    }
}

#[test]
fn rejects_keys_over_1024_chars() {
    // 1029 chars: collection 4 + '/' + 1024 of 'x'
    let long_rkey = "x".repeat(1024);
    let key = format!("coll/{long_rkey}");
    assert!(ensure_valid_mst_key(&key).is_err());
}

#[test]
fn accepts_keys_matching_ts_allow_list() {
    let ok = [
        "coll/3jui7kd54zh2y",
        "coll/self",
        "coll/example.com",
        "com.example/rkey",
        "coll/~1.2-3_",
        "coll/dHJ1ZQ",
        "coll/pre:fix",
        "coll/_",
    ];
    for key in ok {
        ensure_valid_mst_key(key).unwrap_or_else(|e| panic!("key {key:?} should be allowed: {e}"));
    }
}

// -----------------------------------------------------------------------
// countPrefixLen — matches TS utility test exactly.
// -----------------------------------------------------------------------

#[test]
fn count_prefix_len_matches_ts_cases() {
    let cases: &[(&str, &str, usize)] = &[
        ("abc", "abc", 3),
        ("", "abc", 0),
        ("abc", "", 0),
        ("ab", "abc", 2),
        ("abc", "ab", 2),
        ("abcde", "abc", 3),
        ("abc", "abcde", 3),
        ("abcde", "abc1", 3),
        ("abcde", "abb", 2),
        ("abcde", "qbb", 0),
        ("", "asdf", 0),
        ("abc", "abc\x00", 3),
        ("abc\x00", "abc", 3),
    ];
    for (a, b, expected) in cases {
        assert_eq!(
            count_prefix_len(a, b),
            *expected,
            "count_prefix_len({a:?}, {b:?})"
        );
    }
}

// -----------------------------------------------------------------------
// Load round-trip: saving blocks and re-loading must preserve the root CID
// and expose the same leaves. Mirrors TS 'saves and loads from blockstore'.
// -----------------------------------------------------------------------

#[test]
fn save_and_load_preserves_root_and_leaves() {
    let mut mst = MstNode::empty();
    let keys = [
        "com.example.record/3jqfcqzm3fp2j",
        "com.example.record/3jqfcqzm3fr2j",
        "com.example.record/3jqfcqzm3fs2j",
        "com.example.record/3jqfcqzm3ft2j",
        "com.example.record/3jqfcqzm4fc2j",
    ];
    for k in keys {
        mst = add(mst, k);
    }

    let (root, blocks) = mst.get_all_blocks().expect("serialize");
    let reloaded = MstNode::load(&root, &blocks).expect("load");

    // Leaf set must match exactly.
    let orig_leaves: Vec<_> = mst.leaves().into_iter().map(|l| l.key).collect();
    let re_leaves: Vec<_> = reloaded.leaves().into_iter().map(|l| l.key).collect();
    assert_eq!(orig_leaves, re_leaves);

    // Root must match.
    let re_root = reloaded.get_pointer().expect("re-pointer");
    assert_eq!(
        re_root.to_string_base32(),
        root.to_string_base32(),
        "root CID must be preserved across save/load"
    );
}

// -----------------------------------------------------------------------
// Fuzz-ish: the leaves returned by `get_all_blocks` must always round-trip
// through `MstNode::load` and produce an equal tree, for any randomly-
// chosen subset of our interop keys.
// -----------------------------------------------------------------------

#[test]
fn random_subset_roundtrip_through_blocks() {
    let corpus = [
        "com.example.record/3jqfcqzm3fn2j",
        "com.example.record/3jqfcqzm3fo2j",
        "com.example.record/3jqfcqzm3fp2j",
        "com.example.record/3jqfcqzm3fr2j",
        "com.example.record/3jqfcqzm3fs2j",
        "com.example.record/3jqfcqzm3ft2j",
        "com.example.record/3jqfcqzm3fu2j",
        "com.example.record/3jqfcqzm3fx2j",
        "com.example.record/3jqfcqzm3fz2j",
        "com.example.record/3jqfcqzm4fc2j",
        "com.example.record/3jqfcqzm4fd2j",
        "com.example.record/3jqfcqzm4ff2j",
        "com.example.record/3jqfcqzm4fg2j",
        "com.example.record/3jqfcqzm4fh2j",
    ];
    // Deterministic "pseudo-random" subsets via bitmasks. Each mask
    // describes a subset; we round-trip each one.
    for mask in [0b10_1010_1010_1010_u32, 0b1111_0000_1111_u32, 0b1_u32 << 13] {
        let mut mst = MstNode::empty();
        let mut included: Vec<&str> = Vec::new();
        for (i, k) in corpus.iter().enumerate() {
            if mask & (1 << i) != 0 {
                mst = add(mst, k);
                included.push(k);
            }
        }
        let (root, blocks) = mst.get_all_blocks().unwrap();
        let loaded = MstNode::load(&root, &blocks).unwrap();
        let leaves: std::collections::HashSet<_> =
            loaded.leaves().into_iter().map(|l| l.key).collect();
        for k in &included {
            assert!(
                leaves.contains(*k),
                "lost key {k} in roundtrip with mask {mask:b}"
            );
        }
    }
}
