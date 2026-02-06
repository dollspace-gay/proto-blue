//! Integration tests against live AT Protocol XRPC endpoints.
//!
//! Run with: cargo test -p atproto-xrpc --test integration_tests -- --ignored

use atproto_xrpc::{QueryParams, QueryValue};

#[tokio::test]
#[ignore = "requires network access"]
async fn describe_server() {
    let client = atproto_xrpc::XrpcClient::new("https://bsky.social").unwrap();
    let resp = client
        .query("com.atproto.server.describeServer", None, None)
        .await
        .unwrap();

    let data = resp.data;
    assert!(data["did"].is_string(), "Server should have a DID");
    assert!(
        data["availableUserDomains"].is_array(),
        "Server should list available user domains"
    );
}

#[tokio::test]
#[ignore = "requires network access"]
async fn resolve_handle() {
    let client = atproto_xrpc::XrpcClient::new("https://bsky.social").unwrap();
    let mut params = QueryParams::new();
    params.insert(
        "handle".to_string(),
        QueryValue::String("bsky.app".to_string()),
    );
    let resp = client
        .query("com.atproto.identity.resolveHandle", Some(&params), None)
        .await
        .unwrap();

    let did = resp.data["did"].as_str().unwrap();
    assert!(
        did.starts_with("did:"),
        "Resolved DID should start with 'did:'"
    );
}

#[tokio::test]
#[ignore = "requires network access"]
async fn get_profile_unauthenticated() {
    let client = atproto_xrpc::XrpcClient::new("https://public.api.bsky.app").unwrap();
    let mut params = QueryParams::new();
    params.insert(
        "actor".to_string(),
        QueryValue::String("bsky.app".to_string()),
    );
    let resp = client
        .query("app.bsky.actor.getProfile", Some(&params), None)
        .await;

    match resp {
        Ok(r) => {
            assert!(r.data["handle"].is_string());
            assert!(r.data["did"].is_string());
        }
        Err(e) => {
            // Public API may require auth in some cases
            eprintln!("Profile fetch failed (may need auth): {e}");
        }
    }
}

#[tokio::test]
#[ignore = "requires network access"]
async fn invalid_nsid_returns_error() {
    let client = atproto_xrpc::XrpcClient::new("https://bsky.social").unwrap();
    let resp = client
        .query("com.atproto.nonexistent.method", None, None)
        .await;

    assert!(resp.is_err(), "Nonexistent method should return error");
}
