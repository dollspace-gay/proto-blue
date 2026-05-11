#![allow(clippy::pedantic, clippy::nursery)]

use proptest::prelude::*;

use proto_blue_xrpc::error::ResponseType;

#[cfg(feature = "server")]
use proto_blue_xrpc::rate_limit::RateLimiter;
#[cfg(feature = "server")]
use proto_blue_xrpc::{CombinedLimiter, TokenBucketLimiter};
#[cfg(feature = "server")]
use std::sync::Arc;

proptest! {
    /// Any u16 status code should never panic in from_http_status.
    #[test]
    fn from_http_status_never_panics(status in any::<u16>()) {
        let _ = ResponseType::from_http_status(status);
    }

    /// ResponseType::name() should always return a non-empty string.
    #[test]
    fn name_always_returns_non_empty_string(status in any::<u16>()) {
        let rt = ResponseType::from_http_status(status);
        assert!(!rt.name().is_empty());
    }
}

// ── Rate limiter invariants ─────────────────────────────────────────
//
// These tests only exercise the synchronous, deterministic behaviour
// of the bucket: consume N tokens out of a fresh window, observe
// remaining, cross the limit and observe denial, etc. Time-based
// refill isn't property-tested here — it depends on wall-clock
// `Instant::now()` which proptest can't meaningfully generate.
//
// The rate-limiter types live under `proto-blue-xrpc/server`, so
// these tests are feature-gated to match.

#[cfg(feature = "server")]
proptest! {
    /// For any fresh bucket of capacity `cap`, the first `cap` checks
    /// on the same key must succeed, the (cap+1)-th must fail, and
    /// the returned `remaining` must equal `cap - requests_made` at
    /// each step. This is the core accounting contract.
    #[test]
    fn token_bucket_accounts_every_consume(
        cap in 1u64..=50,
        over in 0u64..=10,
    ) {
        let bucket = TokenBucketLimiter::new(cap, 60);
        for i in 0..cap {
            let d = bucket.check("user-1");
            prop_assert!(d.allowed, "check {i} should be allowed");
            prop_assert_eq!(d.limit, cap);
            prop_assert_eq!(d.remaining, cap - (i + 1));
        }
        // Cap exhausted — further requests must be denied. They should
        // still return accurate `limit` metadata for header emission.
        for _ in 0..over {
            let d = bucket.check("user-1");
            prop_assert!(!d.allowed);
            prop_assert_eq!(d.limit, cap);
            prop_assert_eq!(d.remaining, 0);
        }
    }

    /// Different keys share no state: exhausting one bucket must not
    /// affect another. Catches regressions where a global counter
    /// accidentally replaces per-key buckets.
    #[test]
    fn token_bucket_keys_are_independent(
        cap in 1u64..=30,
    ) {
        let bucket = TokenBucketLimiter::new(cap, 60);
        // Drain the "a" bucket.
        for _ in 0..cap {
            prop_assert!(bucket.check("a").allowed);
        }
        prop_assert!(!bucket.check("a").allowed);
        // "b" must still have its full budget.
        let d = bucket.check("b");
        prop_assert!(d.allowed);
        prop_assert_eq!(d.remaining, cap - 1);
    }

    /// `check_with_cost` must consume exactly `points` tokens on an
    /// allowed call — never more, never less. Catches off-by-one bugs
    /// in the multi-token fast path.
    #[test]
    fn token_bucket_cost_consumes_exact_points(
        cap in 5u64..=50,
        cost in 1u32..=5,
    ) {
        let bucket = TokenBucketLimiter::new(cap, 60);
        let d = bucket.check_with_cost("k", cost);
        prop_assert!(d.allowed);
        prop_assert_eq!(d.remaining, cap - u64::from(cost));
    }

    /// The combined limiter returns "denied" the moment any sub-
    /// limiter denies. With sub-limits `a` and `b`, the combined
    /// capacity is `min(a, b)`.
    #[test]
    fn combined_limiter_is_tightest_sub_limiter(
        small in 1u64..=10,
        large in 15u64..=30,
    ) {
        let a: Arc<dyn RateLimiter> = Arc::new(TokenBucketLimiter::new(small, 60));
        let b: Arc<dyn RateLimiter> = Arc::new(TokenBucketLimiter::new(large, 60));
        let combined = CombinedLimiter::new(vec![a, b]);

        for i in 0..small {
            let d = combined.check("k");
            prop_assert!(d.allowed, "combined check {i} should be allowed (small={small})");
        }
        // Small bucket now empty; combined must deny even though
        // large still has budget.
        let d = combined.check("k");
        prop_assert!(!d.allowed);
    }
}
