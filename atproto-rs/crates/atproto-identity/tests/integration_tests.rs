//! Integration tests against live AT Protocol infrastructure.
//!
//! These tests require network access and hit real services.
//! Run with: cargo test -p atproto-identity --test integration_tests -- --ignored

use atproto_identity::{DidResolver, HandleResolver, IdResolver};

#[tokio::test]
#[ignore = "requires network access"]
async fn resolve_did_plc_for_bsky_app() {
    let resolver = DidResolver::new(None, 5000, None);
    let doc = resolver
        .resolve("did:plc:z72i7hdynmk6r22z27h6tvur", false)
        .await
        .unwrap();

    // This is @bsky.app's DID
    let doc = doc.expect("Should resolve bsky.app DID");
    assert_eq!(doc.id, "did:plc:z72i7hdynmk6r22z27h6tvur");
    assert!(!doc.verification_method.is_empty());
    assert!(!doc.service.is_empty());
}

#[tokio::test]
#[ignore = "requires network access"]
async fn resolve_did_web() {
    let resolver = DidResolver::new(None, 5000, None);
    // did:web DIDs resolve via HTTPS
    let result = resolver.resolve("did:web:bsky.social", false).await;
    // May or may not exist - just verify we don't panic
    match result {
        Ok(Some(doc)) => assert!(!doc.id.is_empty()),
        Ok(None) => {} // Not found, OK
        Err(_) => {}   // Expected if did:web:bsky.social doesn't exist
    }
}

#[tokio::test]
#[ignore = "requires network access"]
async fn resolve_handle_via_dns() {
    let resolver = HandleResolver::new(5000);
    let result = resolver.resolve("bsky.app").await;
    match result {
        Ok(Some(did)) => {
            assert!(
                did.starts_with("did:"),
                "Resolved DID should start with 'did:'"
            );
        }
        Ok(None) => {
            eprintln!("Handle resolution returned None");
        }
        Err(e) => {
            // DNS may fail in some environments
            eprintln!("Handle resolution failed (may be expected): {e}");
        }
    }
}

#[tokio::test]
#[ignore = "requires network access"]
async fn id_resolver_full_flow() {
    let resolver = IdResolver::default();

    // Resolve a DID and extract PDS endpoint
    let doc = resolver
        .did
        .resolve("did:plc:z72i7hdynmk6r22z27h6tvur", false)
        .await
        .unwrap();

    let doc = doc.expect("Should resolve bsky.app DID");

    let pds = atproto_common::did_doc::get_pds_endpoint(&doc);
    assert!(
        pds.is_some(),
        "bsky.app's DID document should have a PDS endpoint"
    );

    let signing_key = atproto_common::did_doc::get_signing_key(&doc);
    assert!(
        signing_key.is_some(),
        "bsky.app's DID document should have a signing key"
    );
}
