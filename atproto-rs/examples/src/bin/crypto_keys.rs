//! Example: Cryptographic key operations.
//!
//! Demonstrates generating keypairs, signing/verifying messages,
//! and working with did:key identifiers.
//!
//! Run with: cargo run -p atproto-examples --bin crypto_keys

use atproto_crypto::{ExportableKeypair, Keypair, Signer, Verifier};

fn main() {
    println!("=== AT Protocol Cryptographic Operations ===\n");

    // --- P-256 (ES256) keypair ---
    println!("--- P-256 (ES256) Keypair ---");
    let p256_key = atproto_crypto::P256Keypair::generate();
    let compressed = p256_key.public_key_compressed();
    println!("  Public key (compressed): {} bytes", compressed.len());

    let did_key = atproto_crypto::format_did_key("ES256", &compressed);
    println!("  did:key: {}", did_key);

    // Sign and verify
    let message = b"Hello, AT Protocol!";
    let signature = p256_key.sign(message).unwrap();
    println!("  Signature: {} bytes", signature.len());

    let verifier = atproto_crypto::P256Keypair::verifier_from_compressed(&compressed).unwrap();
    let valid = verifier.verify(message, &signature).unwrap();
    println!(
        "  Verification: {}",
        if valid { "PASSED" } else { "FAILED" }
    );

    // Wrong message should fail
    let wrong_valid = verifier.verify(b"tampered message", &signature).unwrap();
    println!("  Tampered verification: {} (expected false)", wrong_valid);

    // --- K-256 (ES256K / secp256k1) keypair ---
    println!("\n--- K-256 (ES256K / secp256k1) Keypair ---");
    let k256_key = atproto_crypto::K256Keypair::generate();
    let k_compressed = k256_key.public_key_compressed();
    let k_did_key = atproto_crypto::format_did_key("ES256K", &k_compressed);
    println!("  did:key: {}", k_did_key);

    // Export and reimport private key
    let exported = k256_key.export_private_key();
    println!("  Private key exported: {} bytes", exported.len());
    let reimported = atproto_crypto::K256Keypair::from_private_key(&exported).unwrap();
    let sig = reimported.sign(message).unwrap();
    let k_verifier = atproto_crypto::K256Keypair::verifier_from_compressed(&k_compressed).unwrap();
    let valid = k_verifier.verify(message, &sig).unwrap();
    println!(
        "  Reimported key verification: {}",
        if valid { "PASSED" } else { "FAILED" }
    );

    // --- did:key parsing ---
    println!("\n--- did:key Parsing ---");
    let parsed = atproto_crypto::parse_did_key(&did_key).unwrap();
    println!("  Algorithm: {}", parsed.jwt_alg);
    println!("  Key bytes: {} bytes", parsed.key_bytes.len());

    // --- SHA-256 ---
    println!("\n--- SHA-256 ---");
    let hash = atproto_crypto::sha256(b"Hello, world!");
    println!(
        "  SHA-256('Hello, world!'): {}",
        hash.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!("  Hash length: {} bytes (always 32)", hash.len());

    println!("\nDone!");
}
