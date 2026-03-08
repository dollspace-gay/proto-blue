//! Example: Validating AT Protocol identifiers.
//!
//! Demonstrates parsing and validating DIDs, handles, NSIDs, AT-URIs,
//! TIDs, and record keys using the `proto-blue-syntax` crate.
//!
//! Run with: cargo run -p proto-blue-examples --bin syntax_validation

fn main() {
    println!("=== AT Protocol Syntax Validation ===\n");

    // --- DIDs ---
    println!("--- DIDs ---");
    let valid_dids = [
        "did:plc:z72i7hdynmk6r22z27h6tvur",
        "did:web:bsky.social",
        "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
    ];
    for did_str in &valid_dids {
        match proto_blue_syntax::Did::new(did_str) {
            Ok(did) => println!("  Valid DID: {} (method: {})", did, did.method()),
            Err(e) => println!("  Invalid DID '{}': {}", did_str, e),
        }
    }

    let invalid_dids = ["not-a-did", "did:", "did:plc:", "did:123:abc"];
    for did_str in &invalid_dids {
        match proto_blue_syntax::Did::new(did_str) {
            Ok(_) => println!("  Unexpected valid: {}", did_str),
            Err(e) => println!("  Rejected '{}': {}", did_str, e),
        }
    }

    // --- Handles ---
    println!("\n--- Handles ---");
    let handles = [
        "jay.bsky.social",
        "bsky.app",
        "xn--nxasmq6b.bsky.social",
        ".invalid",
        "no-tld",
    ];
    for h in &handles {
        match proto_blue_syntax::Handle::new(h) {
            Ok(handle) => println!("  Valid handle: {}", handle),
            Err(e) => println!("  Invalid '{}': {}", h, e),
        }
    }

    // --- NSIDs ---
    println!("\n--- NSIDs ---");
    let nsids = [
        "com.atproto.repo.createRecord",
        "app.bsky.feed.post",
        "app.bsky.graph.follow",
        "invalid",
    ];
    for n in &nsids {
        match proto_blue_syntax::Nsid::new(n) {
            Ok(nsid) => println!(
                "  Valid NSID: {} (authority: {}, name: {})",
                nsid,
                nsid.authority(),
                nsid.name()
            ),
            Err(e) => println!("  Invalid '{}': {}", n, e),
        }
    }

    // --- AT-URIs ---
    println!("\n--- AT-URIs ---");
    let uris = [
        "at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/3jt5tsfyxya2a",
        "at://jay.bsky.social",
        "at://jay.bsky.social/app.bsky.feed.post",
        "not-an-at-uri",
    ];
    for u in &uris {
        match proto_blue_syntax::AtUri::new(u) {
            Ok(uri) => println!(
                "  Valid AT-URI: {} (authority: {}, collection: {:?}, rkey: {:?})",
                uri,
                uri.authority(),
                uri.collection(),
                uri.rkey()
            ),
            Err(e) => println!("  Invalid '{}': {}", u, e),
        }
    }

    // --- TIDs ---
    println!("\n--- TIDs ---");
    let now_micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let tid = proto_blue_syntax::Tid::from_timestamp(now_micros, 0);
    println!("  Generated TID: {}", tid);
    println!("  TID length: {} chars (always 13)", tid.to_string().len());

    // --- Record Keys ---
    println!("\n--- Record Keys ---");
    let rkeys = ["3jt5tsfyxya2a", "self", ".", ".."];
    for rk in &rkeys {
        match proto_blue_syntax::RecordKey::new(rk) {
            Ok(key) => println!("  Valid record key: {}", key),
            Err(e) => println!("  Invalid '{}': {}", rk, e),
        }
    }

    println!("\nDone!");
}
