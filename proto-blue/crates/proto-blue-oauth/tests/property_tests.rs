use proptest::prelude::*;

use proto_blue_oauth::{DpopKey, generate_pkce, verify_pkce};

proptest! {
    /// PKCE: generate() always produces a verifier between 43 and 128 chars.
    #[test]
    fn pkce_verifier_length(_ in 0..100u32) {
        let pkce = generate_pkce();
        let len = pkce.verifier.len();
        prop_assert!(
            (43..=128).contains(&len),
            "Verifier length {} not in [43, 128]", len
        );
    }

    /// PKCE: generate().verify() always succeeds with the correct verifier.
    #[test]
    fn pkce_verify_own_challenge(_ in 0..100u32) {
        let pkce = generate_pkce();
        prop_assert!(
            verify_pkce(&pkce.verifier, &pkce.challenge),
            "PKCE verification failed for own verifier/challenge pair"
        );
    }

    /// PKCE: different verifiers always produce different challenges.
    #[test]
    fn pkce_different_verifiers_different_challenges(_ in 0..50u32) {
        let a = generate_pkce();
        let b = generate_pkce();
        if a.verifier != b.verifier {
            prop_assert_ne!(
                a.challenge, b.challenge,
                "Different verifiers produced same challenge"
            );
        }
    }

    /// DPoP: generate_dpop_key() always produces a valid key.
    #[test]
    fn dpop_key_generation_valid(_ in 0..20u32) {
        let key = DpopKey::generate().unwrap();
        prop_assert_eq!(&key.public_jwk["kty"], "EC");
        prop_assert_eq!(&key.public_jwk["crv"], "P-256");
        prop_assert!(key.public_jwk.get("x").is_some(), "Missing x coordinate");
        prop_assert!(key.public_jwk.get("y").is_some(), "Missing y coordinate");
        prop_assert!(key.public_jwk.get("d").is_none(), "Public key should not have d");
        prop_assert!(key.private_jwk.get("d").is_some(), "Private key missing d");
    }
}
