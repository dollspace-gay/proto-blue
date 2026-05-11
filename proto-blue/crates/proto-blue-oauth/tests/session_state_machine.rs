#![allow(clippy::pedantic, clippy::nursery)]

//! State-machine property test for [`OAuthSession`] lifecycle
//! invariants.
//!
//! Drives random sequences of `update_token_set` / `token_set` /
//! `did` / `is_expired` calls and asserts invariants hold after
//! every step:
//!
//! 1. `did()` tracks `token_set().sub` exactly — whoever the last
//!    update recorded is who the session claims to be authenticated
//!    as. A silent divergence would let a compromised AS swap
//!    identity under the client's feet.
//! 2. `aud` set on an update persists until the next update that
//!    explicitly overrides it. DPoP `htu` binding depends on this.
//! 3. `is_expired` and `is_expired_jittered` agree at the "clearly
//!    in the past" / "clearly in the future" extremes (the jitter
//!    window only matters in the ±30s band around `now()`).
//!
//! This is a pure-data state machine: no mock HTTP, no refresh lock
//! exercised here (that has its own dedicated integration test in
//! `oauth_integration.rs::session_refresh_dedupes_concurrent_callers`).

#![cfg(feature = "fetch-reqwest")]

use proptest::prelude::*;
use proto_blue_oauth::{DpopKey, DpopNonceCache, OAuthSession, TokenSet};

/// One transition the driver can fire at the session.
#[derive(Debug, Clone)]
enum Transition {
    /// Replace the entire token set. Supplies new (sub, aud,
    /// `access_token`, `refresh_token`, `expires_at`).
    Update {
        sub: String,
        aud: Option<String>,
        access_token: String,
        refresh_token: Option<String>,
        expired_in_past: bool,
    },
}

fn arb_transition() -> impl Strategy<Value = Transition> {
    (
        "[a-z]{3}[0-9]{3}",
        proptest::option::of("[a-z]{3,8}\\.example"),
        "[a-z]{3,10}",
        proptest::option::of("[a-z]{3,10}"),
        any::<bool>(),
    )
        .prop_map(|(sub, aud_host, at, rt, past)| Transition::Update {
            sub: format!("did:plc:{sub}"),
            aud: aud_host.map(|h| format!("https://{h}")),
            access_token: at,
            refresh_token: rt,
            expired_in_past: past,
        })
}

fn build_ts(t: &Transition) -> TokenSet {
    let Transition::Update {
        sub,
        aud,
        access_token,
        refresh_token,
        expired_in_past,
    } = t;
    let expires_at = if *expired_in_past {
        Some("2020-01-01T00:00:00Z".to_string())
    } else {
        Some("2099-01-01T00:00:00Z".to_string())
    };
    TokenSet {
        issuer: "https://as.example".into(),
        sub: sub.clone(),
        scope: "atproto".into(),
        access_token: access_token.clone(),
        refresh_token: refresh_token.clone(),
        token_type: "DPoP".into(),
        expires_at,
        aud: aud.clone(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        .. ProptestConfig::default()
    })]

    #[test]
    fn session_state_matches_last_update(
        transitions in proptest::collection::vec(arb_transition(), 1..20),
    ) {
        // Seed session with an initial token set.
        let seed = build_ts(&Transition::Update {
            sub: "did:plc:seedseedseedseedseedse".into(),
            aud: None,
            access_token: "seed-at".into(),
            refresh_token: None,
            expired_in_past: false,
        });
        let dpop = DpopKey::generate().unwrap();
        let session = OAuthSession::new(seed, dpop, DpopNonceCache::new());

        for t in &transitions {
            let new_ts = build_ts(t);
            let Transition::Update { expired_in_past, .. } = t;
            session.update_token_set(new_ts.clone());

            // 1. did() == token_set().sub == the sub we just set.
            prop_assert_eq!(session.did(), new_ts.sub.clone());
            prop_assert_eq!(session.token_set().sub, new_ts.sub.clone());

            // 2. aud persists through token_set() reads.
            prop_assert_eq!(session.token_set().aud, new_ts.aud.clone());

            // 3. Expiry sign: past timestamp ⇒ is_expired. Future
            //    timestamp ⇒ not expired. (The 10s buffer and ±30s
            //    jitter don't affect "far past" / "far future"
            //    decisions.)
            if *expired_in_past {
                prop_assert!(session.is_expired(), "past token should be expired");
                prop_assert!(session.is_expired_jittered(), "past token should be expired under jitter too");
            } else {
                prop_assert!(!session.is_expired(), "future token should NOT be expired");
                prop_assert!(
                    !session.is_expired_jittered(),
                    "future token should NOT be expired under jitter"
                );
            }
        }
    }
}
