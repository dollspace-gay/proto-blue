//! Example: Merkle Search Tree (MST) operations.
//!
//! Demonstrates building an MST, adding/removing records, serializing
//! to blocks, and CAR file encoding/decoding.
//!
//! Run with: cargo run -p atproto-examples --bin repo_mst

use atproto_lex_data::LexValue;
use atproto_repo::mst::MstNode;

fn make_cid(data: &str) -> atproto_lex_data::Cid {
    atproto_lex_cbor::cid_for_lex(&LexValue::String(data.into())).unwrap()
}

fn main() {
    println!("=== Merkle Search Tree (MST) Operations ===\n");

    // --- Build a tree ---
    println!("--- Building MST ---");
    let mut tree = MstNode::empty();

    let records = [
        ("app.bsky.feed.post/3jt5tsfyxya2a", "Hello world post"),
        ("app.bsky.feed.post/3jt5tsfyxya2b", "Second post"),
        ("app.bsky.feed.like/3jt5tsfyxya2c", "Like record"),
        ("app.bsky.graph.follow/3jt5tsfyxya2d", "Follow record"),
        ("app.bsky.feed.repost/3jt5tsfyxya2e", "Repost record"),
    ];

    for (key, desc) in &records {
        let cid = make_cid(desc);
        tree = tree.add(key, cid).unwrap();
        println!("  Added: {}", key);
    }

    // --- List all leaves ---
    println!("\n--- All leaves (sorted) ---");
    let leaves = tree.leaves();
    println!("  Total records: {}", leaves.len());
    for leaf in &leaves {
        println!("  {} -> {}", leaf.key, leaf.value.to_string_base32());
    }

    // --- Lookup ---
    println!("\n--- Key lookup ---");
    let key = "app.bsky.feed.post/3jt5tsfyxya2a";
    match tree.get(key) {
        Some(cid) => println!("  Found '{}': {}", key, cid.to_string_base32()),
        None => println!("  Not found: {}", key),
    }

    // --- Update ---
    println!("\n--- Update record ---");
    let new_cid = make_cid("Updated post content");
    tree = tree.update(key, new_cid.clone()).unwrap();
    let found = tree.get(key).unwrap();
    println!("  Updated '{}': {}", key, found.to_string_base32());

    // --- Delete ---
    println!("\n--- Delete record ---");
    let del_key = "app.bsky.feed.like/3jt5tsfyxya2c";
    tree = tree.delete(del_key).unwrap();
    println!("  Deleted: {}", del_key);
    println!("  Remaining records: {}", tree.leaves().len());
    assert!(tree.get(del_key).is_none());

    // --- Serialize to blocks ---
    println!("\n--- Serialization ---");
    let (root_cid, blocks) = tree.get_all_blocks().unwrap();
    println!("  Root CID: {}", root_cid.to_string_base32());
    println!("  Total blocks: {}", blocks.len());
    println!("  Total bytes: {}", blocks.byte_size());

    // --- CAR encoding ---
    println!("\n--- CAR file encoding ---");
    let car_bytes = atproto_repo::blocks_to_car(Some(&root_cid), &blocks).unwrap();
    println!("  CAR file size: {} bytes", car_bytes.len());

    // Decode it back
    let (roots, restored_blocks) = atproto_repo::read_car(&car_bytes).unwrap();
    println!("  Decoded roots: {}", roots.len());
    println!("  Decoded blocks: {}", restored_blocks.len());
    assert_eq!(roots[0].to_string_base32(), root_cid.to_string_base32());

    // Reload tree from blocks
    let reloaded = MstNode::load(&root_cid, &restored_blocks).unwrap();
    println!("  Reloaded leaves: {}", reloaded.leaves().len());

    // --- Order independence ---
    println!("\n--- Order independence ---");
    let mut tree_fwd = MstNode::empty();
    let mut tree_rev = MstNode::empty();
    let keys: Vec<String> = (0..20)
        .map(|i| format!("com.example.record/{:04}", i))
        .collect();

    for key in &keys {
        tree_fwd = tree_fwd.add(key, make_cid(key)).unwrap();
    }
    for key in keys.iter().rev() {
        tree_rev = tree_rev.add(key, make_cid(key)).unwrap();
    }

    let (cid_fwd, _) = tree_fwd.get_all_blocks().unwrap();
    let (cid_rev, _) = tree_rev.get_all_blocks().unwrap();
    println!("  Forward root:  {}", cid_fwd.to_string_base32());
    println!("  Reverse root:  {}", cid_rev.to_string_base32());
    println!(
        "  Match: {}",
        if cid_fwd.to_string_base32() == cid_rev.to_string_base32() {
            "YES (deterministic!)"
        } else {
            "NO (bug!)"
        }
    );

    println!("\nDone!");
}
