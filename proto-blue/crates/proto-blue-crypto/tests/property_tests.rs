//! Property-based tests for cryptographic operations.

use proptest::prelude::*;

use proto_blue_crypto::{ExportableKeypair, Keypair, Signer, Verifier};

// --- SHA-256 property tests ---

proptest! {
    #[test]
    fn sha256_deterministic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let hash1 = proto_blue_crypto::sha256(&data);
        let hash2 = proto_blue_crypto::sha256(&data);
        prop_assert_eq!(hash1, hash2);
    }

    #[test]
    fn sha256_always_32_bytes(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let hash = proto_blue_crypto::sha256(&data);
        prop_assert_eq!(hash.len(), 32);
    }

    #[test]
    fn sha256_different_inputs_different_outputs(
        a in proptest::collection::vec(any::<u8>(), 1..256),
        b in proptest::collection::vec(any::<u8>(), 1..256)
    ) {
        prop_assume!(a != b);
        let hash_a = proto_blue_crypto::sha256(&a);
        let hash_b = proto_blue_crypto::sha256(&b);
        prop_assert_ne!(hash_a, hash_b);
    }
}

// --- P-256 key pair property tests ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn p256_sign_verify_roundtrip(_seed in any::<u64>()) {
        let keypair = proto_blue_crypto::P256Keypair::generate();
        let message = b"test message for signing";
        let signature = keypair.sign(message).unwrap();
        let verifier = proto_blue_crypto::P256Keypair::verifier_from_compressed(
            &keypair.public_key_compressed()
        ).unwrap();
        let valid = verifier.verify(message, &signature).unwrap();
        prop_assert!(valid, "Signature should verify against its own public key");
    }

    #[test]
    fn p256_different_messages_different_signatures(
        msg1 in proptest::collection::vec(any::<u8>(), 1..100),
        msg2 in proptest::collection::vec(any::<u8>(), 1..100),
    ) {
        prop_assume!(msg1 != msg2);
        let keypair = proto_blue_crypto::P256Keypair::generate();
        let sig1 = keypair.sign(&msg1).unwrap();
        let sig2 = keypair.sign(&msg2).unwrap();
        prop_assert_ne!(sig1, sig2);
    }

    #[test]
    fn p256_wrong_message_fails_verification(_seed in any::<u64>()) {
        let keypair = proto_blue_crypto::P256Keypair::generate();
        let signature = keypair.sign(b"correct message").unwrap();
        let verifier = proto_blue_crypto::P256Keypair::verifier_from_compressed(
            &keypair.public_key_compressed()
        ).unwrap();
        let valid = verifier.verify(b"wrong message", &signature).unwrap();
        prop_assert!(!valid, "Wrong message should fail verification");
    }
}

// --- K-256 key pair property tests ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn k256_sign_verify_roundtrip(_seed in any::<u64>()) {
        let keypair = proto_blue_crypto::K256Keypair::generate();
        let message = b"test message for k256";
        let signature = keypair.sign(message).unwrap();
        let verifier = proto_blue_crypto::K256Keypair::verifier_from_compressed(
            &keypair.public_key_compressed()
        ).unwrap();
        let valid = verifier.verify(message, &signature).unwrap();
        prop_assert!(valid);
    }

    #[test]
    fn k256_export_reimport(_seed in any::<u64>()) {
        let keypair = proto_blue_crypto::K256Keypair::generate();
        let exported = keypair.export_private_key();
        let reimported = proto_blue_crypto::K256Keypair::from_private_key(&exported).unwrap();
        let msg = b"roundtrip test";
        let sig = keypair.sign(msg).unwrap();
        let verifier = proto_blue_crypto::K256Keypair::verifier_from_compressed(
            &reimported.public_key_compressed()
        ).unwrap();
        let valid = verifier.verify(msg, &sig).unwrap();
        prop_assert!(valid);
    }
}

// --- did:key roundtrip ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn p256_did_key_roundtrip(_seed in any::<u64>()) {
        let keypair = proto_blue_crypto::P256Keypair::generate();
        let compressed = keypair.public_key_compressed();
        let did_key = proto_blue_crypto::format_did_key("ES256", &compressed);
        prop_assert!(did_key.starts_with("did:key:z"));
        let parsed = proto_blue_crypto::parse_did_key(&did_key).unwrap();
        prop_assert_eq!(parsed.jwt_alg, "ES256");
    }

    #[test]
    fn k256_did_key_roundtrip(_seed in any::<u64>()) {
        let keypair = proto_blue_crypto::K256Keypair::generate();
        let compressed = keypair.public_key_compressed();
        let did_key = proto_blue_crypto::format_did_key("ES256K", &compressed);
        prop_assert!(did_key.starts_with("did:key:z"));
        let parsed = proto_blue_crypto::parse_did_key(&did_key).unwrap();
        prop_assert_eq!(parsed.jwt_alg, "ES256K");
    }
}
