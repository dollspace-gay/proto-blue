//! Rate limiting for XRPC handlers.
//!
//! Provides a token-bucket implementation, a "combined" limiter that
//! returns the tightest-of-N decisions, and the data types the
//! server uses to emit standard `RateLimit-*` response headers.
//!
//! The lifecycle:
//!
//! 1. Server receives a request.
//! 2. Server resolves a [`RateLimitKey`] from the request (IP, DID,
//!    custom).
//! 3. Server calls [`RateLimiter::check`] with the key.
//! 4. On `Ok(decision)`, the handler runs; the decision's `limit` /
//!    `remaining` / `reset` become `RateLimit-Limit` /
//!    `RateLimit-Remaining` / `RateLimit-Reset` response headers.
//! 5. On `Err(XrpcServerError::rate_limit_exceeded(decision))`, the
//!    server returns 429 with the same headers plus `Retry-After`.
//!
//! Matches TS `@atproto/xrpc-server`'s `rate-limiter-flexible`-backed
//! limiter semantically (token bucket, per-route + shared, combined
//! tightest-wins) while staying pure-Rust and dependency-free on the
//! hot path.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::error::ResponseType;
use crate::server::XrpcServerError;

/// Outcome of a [`RateLimiter::check`] call.
///
/// Returned on both success and failure; the server emits the
/// `RateLimit-*` headers from this struct regardless of decision so
/// clients can observe their budget even on accepted requests.
#[derive(Debug, Clone)]
pub struct RateLimitDecision {
    /// `true` when the request is permitted.
    pub allowed: bool,
    /// The configured request budget for this window.
    pub limit: u64,
    /// Requests left in the current window (`0` when exceeded).
    pub remaining: u64,
    /// Wall-clock time at which the current window resets.
    pub reset: DateTime<Utc>,
    /// The `RateLimit-Policy` header value — e.g. `"10;w=60"` for a
    /// 10-per-minute policy. Callers can substitute a different
    /// policy string via the builder.
    pub policy: String,
}

impl RateLimitDecision {
    /// Format the headers a caller should emit on a successful
    /// response. Returns a vec of `(header, value)` pairs.
    pub fn headers(&self) -> Vec<(String, String)> {
        vec![
            ("ratelimit-limit".into(), self.limit.to_string()),
            ("ratelimit-remaining".into(), self.remaining.to_string()),
            ("ratelimit-reset".into(), self.reset.timestamp().to_string()),
            ("ratelimit-policy".into(), self.policy.clone()),
        ]
    }

    /// Additional `Retry-After` header — seconds until reset. Only
    /// meaningful on a 429.
    pub fn retry_after_seconds(&self) -> i64 {
        let now = Utc::now();
        (self.reset - now).num_seconds().max(0)
    }
}

/// Limiter trait. Implementations decide whether a request keyed by
/// `key` (and optionally costing `points` > 1 tokens) is allowed.
pub trait RateLimiter: Send + Sync {
    /// Check (and consume) a single point for `key`. Return the
    /// decision; when the budget is exhausted, `allowed = false` and
    /// the server will return 429.
    fn check(&self, key: &str) -> RateLimitDecision;

    /// Check and consume `points` tokens at once. Some methods cost
    /// more than one unit (e.g. bulk operations). Default impl
    /// consumes by looping `points` times; implementations that
    /// support atomic multi-token consumes should override.
    fn check_with_cost(&self, key: &str, points: u32) -> RateLimitDecision {
        // Fallback: call `check` repeatedly, return the last decision.
        // Slow for large `points`; token-bucket overrides this.
        let mut last = self.check(key);
        for _ in 1..points {
            let next = self.check(key);
            // Once denied, stop probing; preserve the last remaining
            // value so response headers reflect real state.
            if !next.allowed {
                last = next;
                break;
            }
            last = next;
        }
        last
    }
}

/// Convert a rate-limit denial into an `XrpcServerError` the server
/// handler path can propagate.
impl XrpcServerError {
    /// Build a 429 from a rate-limit decision, suitable for returning
    /// from a handler when the limit is exhausted.
    pub fn rate_limit_exceeded(decision: &RateLimitDecision) -> Self {
        let retry = decision.retry_after_seconds();
        XrpcServerError {
            status: ResponseType::RateLimitExceeded,
            error: Some("RateLimitExceeded".into()),
            message: Some(format!(
                "rate limit exceeded (retry after {retry}s)",
            )),
            cause: None,
        }
    }
}

// ── Token bucket ────────────────────────────────────────────────────

/// A simple in-memory token-bucket limiter.
///
/// Each `key` owns a bucket of `capacity` tokens. Buckets refill
/// linearly at `refill_per_second` up to `capacity`. Each [`check`]
/// call consumes one token; denials happen when the bucket is empty.
///
/// Thread-safe via a single `Mutex` around the `HashMap`. For
/// higher-throughput deployments swap in a `DashMap`-backed
/// implementation.
///
/// [`check`]: RateLimiter::check
pub struct TokenBucketLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    capacity: u64,
    refill_per_second: f64,
    window_seconds: u64,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucketLimiter {
    /// Construct a bucket that allows `limit` requests per
    /// `window_seconds`. E.g. `new(100, 60)` = 100/minute.
    pub fn new(limit: u64, window_seconds: u64) -> Self {
        assert!(limit > 0, "rate limit must be > 0");
        assert!(window_seconds > 0, "window must be > 0");
        TokenBucketLimiter {
            buckets: Mutex::new(HashMap::new()),
            capacity: limit,
            refill_per_second: limit as f64 / window_seconds as f64,
            window_seconds,
        }
    }

    /// Format `"<limit>;w=<window>"` for the `RateLimit-Policy` header.
    fn policy_string(&self) -> String {
        format!("{};w={}", self.capacity, self.window_seconds)
    }

    /// Remove buckets that haven't been touched in `>= window_seconds`.
    /// Called opportunistically on every `check` to bound memory.
    fn sweep(&self, buckets: &mut HashMap<String, Bucket>, now: Instant) {
        let window = Duration::from_secs(self.window_seconds);
        buckets.retain(|_, b| now.duration_since(b.last_refill) < window);
    }

    /// Core refill+consume logic for `points` tokens.
    fn consume(&self, key: &str, points: u32) -> RateLimitDecision {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap();

        // Opportunistic eviction — bounded by map size, so cheap.
        if buckets.len() > 1024 {
            self.sweep(&mut buckets, now);
        }

        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: self.capacity as f64,
            last_refill: now,
        });

        // Refill.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        let add = elapsed * self.refill_per_second;
        bucket.tokens = (bucket.tokens + add).min(self.capacity as f64);
        bucket.last_refill = now;

        let wanted = points as f64;
        let allowed = bucket.tokens >= wanted;
        if allowed {
            bucket.tokens -= wanted;
        }

        let remaining = bucket.tokens.floor().max(0.0) as u64;
        // Reset = time to fully-refilled bucket. We report the next
        // "full" reset rather than per-token to keep the header
        // stable under rapid sampling.
        let seconds_to_reset =
            (self.capacity as f64 - bucket.tokens) / self.refill_per_second.max(1e-9);
        let reset =
            Utc::now() + chrono::Duration::seconds(seconds_to_reset.ceil() as i64);

        RateLimitDecision {
            allowed,
            limit: self.capacity,
            remaining,
            reset,
            policy: self.policy_string(),
        }
    }
}

impl RateLimiter for TokenBucketLimiter {
    fn check(&self, key: &str) -> RateLimitDecision {
        self.consume(key, 1)
    }

    fn check_with_cost(&self, key: &str, points: u32) -> RateLimitDecision {
        // Atomic: single Mutex take, single refill computation.
        self.consume(key, points.max(1))
    }
}

// ── Combined limiter ────────────────────────────────────────────────

/// Runs every child limiter and returns the tightest decision —
/// denied if any limiter denies, else the one with the smallest
/// `remaining` (so the response headers reflect the worst bucket).
pub struct CombinedLimiter {
    limiters: Vec<Arc<dyn RateLimiter>>,
}

impl CombinedLimiter {
    pub fn new(limiters: Vec<Arc<dyn RateLimiter>>) -> Self {
        assert!(!limiters.is_empty(), "CombinedLimiter needs ≥ 1 child");
        CombinedLimiter { limiters }
    }
}

impl RateLimiter for CombinedLimiter {
    fn check(&self, key: &str) -> RateLimitDecision {
        let mut decisions: Vec<RateLimitDecision> =
            self.limiters.iter().map(|l| l.check(key)).collect();

        // If any denied, take the denied decision with smallest
        // `remaining` — that's the earliest reset the caller cares about.
        if let Some(denied) = decisions
            .iter()
            .filter(|d| !d.allowed)
            .min_by_key(|d| d.remaining)
        {
            return denied.clone();
        }

        // All allowed — pick the tightest (smallest `remaining`).
        decisions.sort_by_key(|d| d.remaining);
        decisions.into_iter().next().expect("non-empty")
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_within_capacity() {
        let lim = TokenBucketLimiter::new(3, 60);
        for _ in 0..3 {
            assert!(lim.check("alice").allowed);
        }
        let denied = lim.check("alice");
        assert!(!denied.allowed);
        assert_eq!(denied.limit, 3);
        assert_eq!(denied.remaining, 0);
    }

    #[test]
    fn token_bucket_separate_keys_have_separate_budgets() {
        let lim = TokenBucketLimiter::new(2, 60);
        for _ in 0..2 {
            assert!(lim.check("alice").allowed);
        }
        assert!(!lim.check("alice").allowed);
        assert!(lim.check("bob").allowed, "bob has his own budget");
    }

    #[test]
    fn token_bucket_refills() {
        let lim = TokenBucketLimiter::new(10, 1); // 10/sec
        for _ in 0..10 {
            assert!(lim.check("x").allowed);
        }
        assert!(!lim.check("x").allowed);

        // Poke the internals: backdate `last_refill` so the next check
        // refills the bucket without sleeping.
        {
            let mut buckets = lim.buckets.lock().unwrap();
            let b = buckets.get_mut("x").unwrap();
            b.last_refill = Instant::now() - Duration::from_secs(2);
        }
        assert!(lim.check("x").allowed, "bucket should have refilled");
    }

    #[test]
    fn token_bucket_check_with_cost_multi() {
        let lim = TokenBucketLimiter::new(10, 60);
        let d = lim.check_with_cost("x", 5);
        assert!(d.allowed);
        assert_eq!(d.remaining, 5);
        // 5 + 5 = 10 exact; next single check drains to 4 left
        let _ = lim.check_with_cost("x", 5);
        let next = lim.check("x");
        assert!(!next.allowed);
    }

    #[test]
    fn decision_headers_include_all_four() {
        let lim = TokenBucketLimiter::new(5, 60);
        let d = lim.check("x");
        let h = d.headers();
        let names: Vec<&str> = h.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"ratelimit-limit"));
        assert!(names.contains(&"ratelimit-remaining"));
        assert!(names.contains(&"ratelimit-reset"));
        assert!(names.contains(&"ratelimit-policy"));
    }

    #[test]
    fn combined_denies_if_any_child_denies() {
        let tight = Arc::new(TokenBucketLimiter::new(1, 60)) as Arc<dyn RateLimiter>;
        let loose = Arc::new(TokenBucketLimiter::new(100, 60)) as Arc<dyn RateLimiter>;
        let combined = CombinedLimiter::new(vec![tight.clone(), loose.clone()]);

        assert!(combined.check("x").allowed, "first call consumes both");
        let d = combined.check("x");
        assert!(!d.allowed, "tight child denied");
        // Denial decision should reflect the tight bucket's reset.
        assert_eq!(d.limit, 1);
    }

    #[test]
    fn combined_picks_tightest_remaining_when_all_allow() {
        let a = Arc::new(TokenBucketLimiter::new(100, 60)) as Arc<dyn RateLimiter>;
        let b = Arc::new(TokenBucketLimiter::new(10, 60)) as Arc<dyn RateLimiter>;
        let combined = CombinedLimiter::new(vec![a, b]);
        let d = combined.check("x");
        assert!(d.allowed);
        // The tighter (b) has `remaining = 9`; the looser (a) has 99.
        assert_eq!(d.remaining, 9);
    }

    #[test]
    fn xrpc_error_from_decision_is_429() {
        let lim = TokenBucketLimiter::new(1, 60);
        let _ = lim.check("x");
        let d = lim.check("x");
        let err = XrpcServerError::rate_limit_exceeded(&d);
        assert_eq!(err.status, ResponseType::RateLimitExceeded);
        assert_eq!(err.error.as_deref(), Some("RateLimitExceeded"));
    }

    #[test]
    fn retry_after_is_positive_after_denial() {
        let lim = TokenBucketLimiter::new(1, 60);
        let _ = lim.check("x");
        let d = lim.check("x");
        assert!(!d.allowed);
        assert!(d.retry_after_seconds() > 0);
    }
}

