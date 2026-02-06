//! Exponential backoff retry utility.

use std::future::Future;
use std::time::Duration;

/// Options for retry behavior.
pub struct RetryOptions {
    /// Maximum number of retries (default: 3).
    pub max_retries: usize,
    /// Custom delay function. Returns the delay for retry number `n`,
    /// or `None` to stop retrying. Default: exponential backoff.
    pub get_wait_ms: Option<Box<dyn Fn(usize) -> Option<u64> + Send + Sync>>,
}

impl Default for RetryOptions {
    fn default() -> Self {
        RetryOptions {
            max_retries: 3,
            get_wait_ms: None,
        }
    }
}

/// Retry an async function with exponential backoff.
///
/// The `retryable` predicate determines whether a given error should trigger
/// a retry. By default, all errors are retried.
pub async fn retry<T, E, Fut, F, R>(f: F, retryable: R, opts: RetryOptions) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    R: Fn(&E) -> bool,
{
    let max_retries = opts.max_retries;
    let get_wait_ms = opts
        .get_wait_ms
        .unwrap_or_else(|| Box::new(|n| Some(backoff_ms(n, 100, 1000))));

    let mut retries = 0;
    loop {
        match f().await {
            Ok(val) => return Ok(val),
            Err(err) => {
                let wait_ms = get_wait_ms(retries);
                let will_retry = retries < max_retries && wait_ms.is_some() && retryable(&err);
                if will_retry {
                    retries += 1;
                    if let Some(ms) = wait_ms {
                        if ms > 0 {
                            tokio::time::sleep(Duration::from_millis(ms)).await;
                        }
                    }
                } else {
                    return Err(err);
                }
            }
        }
    }
}

/// Retry all errors (convenience wrapper).
pub async fn retry_all<T, E, Fut, F>(f: F, opts: RetryOptions) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    retry(f, |_: &E| true, opts).await
}

/// Calculate exponential backoff delay with jitter.
///
/// Produces delays: ~100ms, ~200ms, ~400ms, ~800ms, ~1000ms, ~1000ms, ...
pub fn backoff_ms(n: usize, multiplier: u64, max: u64) -> u64 {
    let exponential = (2u64.pow(n as u32)).saturating_mul(multiplier);
    let ms = exponential.min(max);
    jitter(ms)
}

/// Add +/-15% random jitter to a value.
fn jitter(value: u64) -> u64 {
    let delta = (value as f64) * 0.15;
    use rand::Rng;
    let offset = rand::thread_rng().gen_range(-delta..delta);
    (value as f64 + offset).round().max(0.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_ms_exponential() {
        // Should roughly double each time (with jitter)
        for _ in 0..10 {
            let d0 = backoff_ms(0, 100, 1000);
            let d1 = backoff_ms(1, 100, 1000);
            let d2 = backoff_ms(2, 100, 1000);
            // d0 ~= 100, d1 ~= 200, d2 ~= 400 (with +/-15% jitter)
            assert!(d0 >= 85 && d0 <= 115, "d0={d0}");
            assert!(d1 >= 170 && d1 <= 230, "d1={d1}");
            assert!(d2 >= 340 && d2 <= 460, "d2={d2}");
        }
    }

    #[test]
    fn backoff_ms_capped() {
        let d = backoff_ms(10, 100, 1000);
        // 2^10 * 100 = 102400, but capped at 1000 +/- 15%
        assert!(d >= 850 && d <= 1150, "d={d}");
    }

    #[tokio::test]
    async fn retry_succeeds_immediately() {
        let result: Result<i32, &str> =
            retry_all(|| async { Ok(42) }, RetryOptions::default()).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn retry_gives_up_after_max() {
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = call_count.clone();

        let result: Result<i32, &str> = retry_all(
            || {
                let count = count.clone();
                async move {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Err("always fails")
                }
            },
            RetryOptions {
                max_retries: 2,
                get_wait_ms: Some(Box::new(|_| Some(0))), // No delay for tests
            },
        )
        .await;

        assert!(result.is_err());
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "1 initial + 2 retries"
        );
    }
}
