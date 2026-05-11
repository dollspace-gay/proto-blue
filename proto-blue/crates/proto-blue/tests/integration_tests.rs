#![allow(clippy::pedantic, clippy::nursery)]

use proto_blue::lex_data::LexValue;
use std::collections::BTreeMap;

/// 1. Parse a DID through proto_blue::syntax::Did
#[test]
fn parse_did() {
    let did = proto_blue::syntax::Did::new("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
    assert_eq!(did.method(), "plc");
    assert_eq!(did.as_str(), "did:plc:z72i7hdynmk6r22z27h6tvur");

    // Invalid DIDs should fail
    assert!(proto_blue::syntax::Did::new("not-a-did").is_err());
    assert!(proto_blue::syntax::Did::new("did:").is_err());
}

/// 2. Parse a Handle through proto_blue::syntax::Handle
#[test]
fn parse_handle() {
    let handle = proto_blue::syntax::Handle::new("alice.bsky.social").unwrap();
    assert_eq!(handle.as_str(), "alice.bsky.social");

    // Handles are normalized to lowercase
    let upper = proto_blue::syntax::Handle::new("Alice.Bsky.Social").unwrap();
    assert_eq!(upper.as_str(), "alice.bsky.social");

    // Invalid handles should fail
    assert!(proto_blue::syntax::Handle::new("noperiod").is_err());
    assert!(proto_blue::syntax::Handle::new("").is_err());
}

/// 3. Create a P256Keypair through proto_blue::crypto, sign and verify
#[test]
fn crypto_sign_and_verify() {
    use proto_blue::crypto::{Keypair, P256Keypair, Signer, Verifier};

    let kp = P256Keypair::generate();
    let msg = b"Hello, AT Protocol!";
    let sig = kp.sign(msg).unwrap();

    // Verify using a verifier from the compressed public key
    let compressed = kp.public_key_compressed();
    let verifier = P256Keypair::verifier_from_compressed(&compressed).unwrap();
    assert!(verifier.verify(msg, &sig).unwrap());

    // Wrong message should fail verification
    assert!(!verifier.verify(b"wrong message", &sig).unwrap());

    // did:key should start with the expected prefix
    let did = kp.did();
    assert!(did.starts_with("did:key:z"));
}

/// 4. Encode/decode a LexValue through proto_blue::lex_cbor
#[test]
fn lex_cbor_encode_decode() {
    let mut map = BTreeMap::new();
    map.insert("name".into(), LexValue::String("Alice".into()));
    map.insert("age".into(), LexValue::Integer(30));
    map.insert("active".into(), LexValue::Bool(true));
    let value = LexValue::Map(map);

    let encoded = proto_blue::lex_cbor::encode(&value).unwrap();
    let decoded = proto_blue::lex_cbor::decode(&encoded).unwrap();
    assert_eq!(value, decoded);

    // CID should be deterministic
    let cid1 = proto_blue::lex_cbor::cid_for_lex(&value).unwrap();
    let cid2 = proto_blue::lex_cbor::cid_for_lex(&value).unwrap();
    assert_eq!(cid1, cid2);
}

/// 5. Convert JSON to LexValue through proto_blue::lex_json
#[test]
fn lex_json_conversion() {
    let json = serde_json::json!({
        "text": "Hello!",
        "count": 42,
        "active": true,
        "nothing": null
    });

    let lex = proto_blue::lex_json::json_to_lex(&json);
    let map = lex.as_map().unwrap();
    assert_eq!(map.get("text").unwrap().as_str(), Some("Hello!"));
    assert_eq!(map.get("count").unwrap().as_integer(), Some(42));
    assert_eq!(map.get("active").unwrap().as_bool(), Some(true));
    assert!(map.get("nothing").unwrap().is_null());

    // Roundtrip back to JSON
    let back = proto_blue::lex_json::lex_to_json(&lex);
    assert_eq!(back["text"], "Hello!");
    assert_eq!(back["count"], 42);

    // String serialize/parse roundtrip
    let stringified = proto_blue::lex_json::lex_stringify(&lex);
    let parsed = proto_blue::lex_json::lex_parse(&stringified).unwrap();
    assert_eq!(lex, parsed);
}

/// 6. Build an XRPC client through proto_blue::xrpc
#[test]
fn xrpc_client_construction() {
    let client = proto_blue::xrpc::XrpcClient::new("https://bsky.social").unwrap();
    assert_eq!(client.service_url().as_str(), "https://bsky.social/");

    // With trailing slash
    let client2 = proto_blue::xrpc::XrpcClient::new("https://bsky.social/").unwrap();
    assert_eq!(client2.service_url().as_str(), "https://bsky.social/");

    // Invalid URL should error
    assert!(proto_blue::xrpc::XrpcClient::new("not a url").is_err());
}

/// 7. Create a PKCE challenge through proto_blue::oauth
#[test]
fn oauth_pkce() {
    let pkce = proto_blue::oauth::generate_pkce();
    assert_eq!(pkce.method, "S256");
    assert!(!pkce.verifier.is_empty());
    assert!(!pkce.challenge.is_empty());
    assert_ne!(pkce.verifier, pkce.challenge);

    // Verification should succeed with correct verifier
    assert!(proto_blue::oauth::verify_pkce(
        &pkce.verifier,
        &pkce.challenge
    ));

    // Verification should fail with wrong verifier
    assert!(!proto_blue::oauth::verify_pkce(
        "wrong_verifier",
        &pkce.challenge
    ));
}

/// 8. Generate a TID through proto_blue::common
#[test]
fn common_tid_generation() {
    let tid1 = proto_blue::common::next_tid(None);
    let tid2 = proto_blue::common::next_tid(None);

    // TIDs should be valid 13-char strings
    assert_eq!(tid1.as_str().len(), 13);
    assert_eq!(tid2.as_str().len(), 13);

    // TIDs should be monotonically increasing
    assert!(
        tid2.as_str() > tid1.as_str(),
        "Expected tid2 ({}) > tid1 ({})",
        tid2.as_str(),
        tid1.as_str()
    );

    // All characters should be in base32-sortable charset
    for ch in tid1.as_str().chars() {
        assert!(
            ('2'..='7').contains(&ch) || ch.is_ascii_lowercase(),
            "TID character '{}' not in [2-7a-z]",
            ch
        );
    }
}
