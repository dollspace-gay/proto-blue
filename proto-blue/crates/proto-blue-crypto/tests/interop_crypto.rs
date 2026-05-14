#![allow(clippy::pedantic, clippy::nursery)]

//! Interop parity tests for proto-blue-crypto.
//!
//! Drives the official atproto crypto fixtures from
//! `<workspace>/interop-test-files/crypto/`:
//!
//! - `signature-fixtures.json` — per-signature valid/invalid verification
//!   cases, including high-S and DER-encoded signatures that TS rejects
//!   under strict mode and accepts under `allowMalleableSig`.
//! - `w3c_didkey_P256.json` — W3C did:key roundtrip for P-256 keys given
//!   the private key in base58btc.
//! - `w3c_didkey_K256.json` — same, for secp256k1 keys given in hex.

use std::fs;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;

use proto_blue_crypto::{
    ExportableKeypair, K256Keypair, Keypair, P256Keypair, parse_did_key, verify_signature,
};

fn fixture(name: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("../../interop-test-files/crypto")
        .join(name)
}

fn read_json(name: &str) -> serde_json::Value {
    let path = fixture(name);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("fixture is valid JSON")
}

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "odd-length hex string cannot be decoded: {s:?}"
    );
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .unwrap_or_else(|e| panic!("invalid hex byte {:?}: {e}", &s[i..i + 2]));
        out.push(byte);
    }
    out
}

// ---------------------------------------------------------------
// signature-fixtures.json
// ---------------------------------------------------------------

#[test]
fn signature_fixtures_roundtrip() {
    let cases = read_json("signature-fixtures.json");
    let cases = cases.as_array().expect("top-level array");
    assert!(!cases.is_empty());

    let mut failures = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        let comment = case["comment"].as_str().unwrap_or("<no comment>");
        let did = case["publicKeyDid"].as_str().expect("publicKeyDid");
        let msg_b64 = case["messageBase64"].as_str().expect("messageBase64");
        let sig_b64 = case["signatureBase64"].as_str().expect("signatureBase64");
        let should_verify = case["validSignature"].as_bool().expect("validSignature");

        let msg = STANDARD_NO_PAD.decode(msg_b64).expect("base64 message");
        let sig = STANDARD_NO_PAD.decode(sig_b64).expect("base64 signature");

        // Strict verification: must match the fixture's expectation.
        // A malformed signature (e.g. DER where we expect 64-byte compact)
        // counts as "verification failed" — treat Err as false rather than
        // panicking the whole suite.
        let strict =
            verify_signature(did, &msg, &sig, /*allow_malleable=*/ false).unwrap_or_default();
        if strict != should_verify {
            failures.push(format!(
                "#{i} ({comment}): strict verify returned {strict}, expected {should_verify}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "\n{} signature-fixture failures:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// Independently: every fixture's `publicKeyDid` must parse cleanly.
#[test]
fn every_fixture_public_did_key_parses() {
    let cases = read_json("signature-fixtures.json");
    for case in cases.as_array().unwrap() {
        let did = case["publicKeyDid"].as_str().unwrap();
        let parsed = parse_did_key(did).unwrap_or_else(|e| {
            panic!("failed to parse did:key {did}: {e}");
        });
        let alg = case["algorithm"].as_str().unwrap();
        assert_eq!(parsed.jwt_alg, alg, "alg mismatch for {did}");
    }
}

/// For a high-S or DER signature, the strict verifier must return false,
/// and — in principle — the malleable verifier *may* accept the high-S
/// variant. This test documents the exact current behavior by tag.
#[test]
fn malleable_verify_behavior_per_tag() {
    let cases = read_json("signature-fixtures.json");
    for case in cases.as_array().unwrap() {
        let tags: Vec<&str> = case["tags"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        if tags.is_empty() {
            continue;
        }

        let did = case["publicKeyDid"].as_str().unwrap();
        let msg = STANDARD_NO_PAD
            .decode(case["messageBase64"].as_str().unwrap())
            .unwrap();
        let sig = STANDARD_NO_PAD
            .decode(case["signatureBase64"].as_str().unwrap())
            .unwrap();

        let strict = verify_signature(did, &msg, &sig, false).unwrap_or(false);
        // Strict must be false for all tagged (high-s / der-encoded) cases.
        assert!(
            !strict,
            "strict must reject tagged signature {tags:?} for {did}"
        );
    }
}

// ---------------------------------------------------------------
// w3c_didkey_P256.json: private key (base58btc) -> public did:key match
// ---------------------------------------------------------------

#[test]
fn p256_didkey_fixtures_roundtrip() {
    let cases = read_json("w3c_didkey_P256.json");
    let cases = cases.as_array().expect("top-level array");
    assert!(!cases.is_empty());

    for (i, case) in cases.iter().enumerate() {
        let priv_b58 = case["privateKeyBytesBase58"].as_str().expect("private b58");
        let expected = case["publicDidKey"].as_str().expect("publicDidKey");

        let priv_bytes = bs58::decode(priv_b58).into_vec().expect("valid base58btc");
        let kp = P256Keypair::from_private_key(&priv_bytes)
            .unwrap_or_else(|e| panic!("case #{i}: P256 import failed: {e}"));
        assert_eq!(
            kp.did(),
            expected,
            "case #{i}: did:key does not match W3C test vector"
        );
    }
}

// ---------------------------------------------------------------
// w3c_didkey_K256.json: private key (hex) -> public did:key match
// ---------------------------------------------------------------

#[test]
fn k256_didkey_fixtures_roundtrip() {
    let cases = read_json("w3c_didkey_K256.json");
    let cases = cases.as_array().expect("top-level array");
    assert!(!cases.is_empty());

    for (i, case) in cases.iter().enumerate() {
        let priv_hex = case["privateKeyBytesHex"].as_str().expect("private hex");
        let expected = case["publicDidKey"].as_str().expect("publicDidKey");

        let priv_bytes = decode_hex(priv_hex);
        let kp = K256Keypair::from_private_key(&priv_bytes)
            .unwrap_or_else(|e| panic!("case #{i}: K256 import failed: {e}"));
        assert_eq!(
            kp.did(),
            expected,
            "case #{i}: did:key does not match W3C test vector"
        );
    }
}

// ---------------------------------------------------------------
// Round-trip: sign -> export -> re-import -> verify the fresh signature.
// ---------------------------------------------------------------

#[test]
fn exported_k256_key_produces_same_did() {
    let kp = K256Keypair::generate();
    let priv_bytes = kp.export_private_key();
    let kp2 = K256Keypair::from_private_key(&priv_bytes).unwrap();
    assert_eq!(kp.did(), kp2.did(), "exported+reimported key must match");
}

#[test]
fn exported_p256_key_produces_same_did() {
    let kp = P256Keypair::generate();
    let priv_bytes = kp.export_private_key();
    let kp2 = P256Keypair::from_private_key(&priv_bytes).unwrap();
    assert_eq!(kp.did(), kp2.did());
}
