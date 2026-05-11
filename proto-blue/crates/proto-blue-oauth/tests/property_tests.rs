#![allow(clippy::pedantic, clippy::nursery)]

use proptest::prelude::*;

use proto_blue_oauth::{DpopKey, Scope, ScopeSet, generate_pkce, verify_pkce};

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

// --- Scope parser round-trip + set semantics ---

/// Generate a single valid scope token.
fn arb_scope() -> impl Strategy<Value = Scope> {
    prop_oneof![
        Just(Scope::Atproto),
        Just(Scope::TransitionEmail),
        Just(Scope::TransitionGeneric),
        Just(Scope::TransitionChatBsky),
    ]
}

proptest! {
    /// `Scope::parse(scope.to_string()) == Ok(scope)` for any valid
    /// scope. The canonical `Display` form must round-trip through
    /// the parser.
    #[test]
    fn scope_display_roundtrip(scope in arb_scope()) {
        let s = scope.to_string();
        let reparsed = Scope::parse(&s).expect("Display output must re-parse");
        prop_assert_eq!(reparsed, scope);
    }

    /// `Scope::parse` must never panic on arbitrary input.
    #[test]
    fn scope_parse_never_panics(s in ".*") {
        let _ = Scope::parse(&s);
    }

    /// `ScopeSet::parse(set.to_string())` must yield an equal set.
    /// This is the full round-trip the OAuth AS↔client boundary
    /// depends on.
    #[test]
    fn scope_set_display_roundtrip(
        scopes in proptest::collection::vec(arb_scope(), 0..6)
    ) {
        let mut set = ScopeSet::default();
        for s in scopes {
            set.insert(s);
        }
        let rendered = set.to_string();
        let reparsed = ScopeSet::parse(&rendered).expect("ScopeSet must re-parse");
        prop_assert_eq!(set, reparsed);
    }

    /// `contains` agrees with "did it insert as new-or-already-present".
    /// After `insert(x)`, `contains(&x)` is true; after `insert` of
    /// something else, `contains(&x)` still holds.
    #[test]
    fn scope_set_contains_reflects_insertions(
        scopes in proptest::collection::vec(arb_scope(), 1..5)
    ) {
        let mut set = ScopeSet::default();
        for s in &scopes {
            set.insert(s.clone());
            prop_assert!(set.contains(s));
        }
        for s in &scopes {
            prop_assert!(set.contains(s));
        }
    }

    /// `ScopeSet::parse` never panics.
    #[test]
    fn scope_set_parse_never_panics(s in ".*") {
        let _ = ScopeSet::parse(&s);
    }
}
