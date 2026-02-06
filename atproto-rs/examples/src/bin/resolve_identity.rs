//! Example: Resolving AT Protocol identities.
//!
//! Demonstrates resolving DIDs and handles using the identity crate.
//! Requires network access to reach bsky.social and PLC directory.
//!
//! Run with: cargo run -p atproto-examples --bin resolve_identity

use atproto_identity::{DidResolver, HandleResolver, IdResolver};

#[tokio::main]
async fn main() {
    println!("=== AT Protocol Identity Resolution ===\n");
    println!("(requires network access)\n");

    // --- Resolve a DID ---
    println!("--- DID Resolution ---");
    let did_resolver = DidResolver::new(None, 5000, None);

    let did = "did:plc:z72i7hdynmk6r22z27h6tvur"; // @bsky.app
    println!("  Resolving: {}", did);
    match did_resolver.resolve(did, false).await {
        Ok(Some(doc)) => {
            println!("  DID: {}", doc.id);
            if !doc.also_known_as.is_empty() {
                println!("  Also known as: {:?}", doc.also_known_as);
            }
            println!("  Verification methods: {}", doc.verification_method.len());
            println!("  Services: {}", doc.service.len());

            // Extract PDS endpoint
            let pds = atproto_common::did_doc::get_pds_endpoint(&doc);
            println!("  PDS endpoint: {:?}", pds);

            // Extract signing key
            let signing_key = atproto_common::did_doc::get_signing_key(&doc);
            if let Some(key) = signing_key {
                println!("  Signing key type: {}", key.key_type);
            }
        }
        Ok(None) => println!("  DID not found"),
        Err(e) => println!("  Error: {}", e),
    }

    // --- Resolve a handle ---
    println!("\n--- Handle Resolution ---");
    let handle_resolver = HandleResolver::new(5000);

    let handle = "bsky.app";
    println!("  Resolving handle: {}", handle);
    match handle_resolver.resolve(handle).await {
        Ok(Some(resolved_did)) => println!("  Resolved to: {}", resolved_did),
        Ok(None) => println!("  Handle not found"),
        Err(e) => println!("  Error: {}", e),
    }

    // --- Combined resolver ---
    println!("\n--- Combined IdResolver ---");
    let resolver = IdResolver::default();

    let handles_to_resolve = ["bsky.app", "atproto.com"];
    for h in &handles_to_resolve {
        print!("  {} -> ", h);
        match resolver.handle.resolve(h).await {
            Ok(Some(did)) => {
                println!("{}", did);
                // Now resolve the DID document
                match resolver.did.resolve(&did, false).await {
                    Ok(Some(doc)) => {
                        let pds = atproto_common::did_doc::get_pds_endpoint(&doc);
                        println!("    PDS: {:?}", pds);
                    }
                    Ok(None) => println!("    (DID document not found)"),
                    Err(e) => println!("    (DID resolution error: {})", e),
                }
            }
            Ok(None) => println!("(not found)"),
            Err(e) => println!("(error: {})", e),
        }
    }

    println!("\nDone!");
}
