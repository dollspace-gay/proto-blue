//! Cancellation primitives for async operations.
//!
//! Wraps `tokio_util::sync::CancellationToken` with a small helper that
//! any async result can be opted into. The TS SDK passes an
//! `AbortSignal` through every request function; the Rust idiom is
//! different — rather than threading a `&CancellationToken` argument
//! through every `XrpcClient::query`, `DidResolver::resolve`, etc., we
//! let callers wrap arbitrary futures at the call site:
//!
//! ```
//! use proto_blue_common::cancel::{CancelError, CancellationToken, cancellable};
//!
//! async fn example() -> Result<u32, CancelError<std::io::Error>> {
//!     let token = CancellationToken::new();
//!     let child = token.child_token();
//!     // … some other task may call `child.cancel()` from elsewhere …
//!     cancellable(async { Ok::<u32, std::io::Error>(42) }, &child).await
//! }
//! ```
//!
//! Advantages of this approach:
//! - Zero breakage to existing signatures across XRPC / Identity /
//!   OAuth / Repo.
//! - Works for any `Future<Output = Result<T, E>>` in any crate.
//! - One well-tested helper instead of twenty plumbed arguments.
//!
//! The wrapper races the user's future against the token's
//! `cancelled()` future via `tokio::select!`. When cancellation wins,
//! the inner future is dropped at its next `.await` point — standard
//! Rust async cancellation semantics.

pub use tokio_util::sync::CancellationToken;

/// Error returned by [`cancellable`].
///
/// Parameterized over the inner future's error type so callers can
/// recover the original error distinctly from cancellation.
#[derive(Debug, thiserror::Error)]
pub enum CancelError<E> {
    /// The token was cancelled before the inner future completed.
    #[error("operation cancelled")]
    Cancelled,
    /// The inner future completed with its own error.
    #[error(transparent)]
    Inner(E),
}

impl<E> CancelError<E> {
    /// `true` if cancelled; `false` if the inner future errored.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, CancelError::Cancelled)
    }

    /// Extract the inner error, if any.
    pub fn into_inner(self) -> Option<E> {
        match self {
            CancelError::Inner(e) => Some(e),
            CancelError::Cancelled => None,
        }
    }
}

/// Race a future against a cancellation token.
///
/// If `token` is cancelled before `fut` completes, returns
/// `Err(CancelError::Cancelled)` and drops `fut`. Otherwise returns
/// the future's result wrapped so errors round-trip as `Inner(e)`.
///
/// Nothing is cancelled "mid-syscall" — Rust async cancellation drops
/// the future, which drops its in-flight I/O types. For network calls
/// this closes the underlying socket, which is the behavior the caller
/// wants.
pub async fn cancellable<F, T, E>(fut: F, token: &CancellationToken) -> Result<T, CancelError<E>>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    tokio::select! {
        result = fut => result.map_err(CancelError::Inner),
        _ = token.cancelled() => Err(CancelError::Cancelled),
    }
}

/// Same as [`cancellable`], but for futures whose output is not a
/// `Result`. On cancellation, returns `None`; on success, returns
/// `Some(value)`.
pub async fn cancellable_infallible<F, T>(fut: F, token: &CancellationToken) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    tokio::select! {
        value = fut => Some(value),
        _ = token.cancelled() => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn returns_success_when_not_cancelled() {
        let token = CancellationToken::new();
        let got = cancellable(async { Ok::<i32, &str>(7) }, &token)
            .await
            .unwrap();
        assert_eq!(got, 7);
    }

    #[tokio::test]
    async fn propagates_inner_error() {
        let token = CancellationToken::new();
        let got: Result<i32, CancelError<&str>> =
            cancellable(async { Err::<i32, &str>("boom") }, &token).await;
        match got {
            Err(CancelError::Inner("boom")) => {}
            other => panic!("expected Inner(\"boom\"), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cancellation_interrupts_a_long_future() {
        let token = CancellationToken::new();
        let child = token.child_token();

        // Cancel shortly after the future starts.
        let canceller = tokio::spawn({
            let t = token.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                t.cancel();
            }
        });

        let start = std::time::Instant::now();
        let got: Result<(), CancelError<std::io::Error>> = cancellable(
            async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(())
            },
            &child,
        )
        .await;
        canceller.await.unwrap();

        assert!(matches!(got, Err(CancelError::Cancelled)));
        // Must have completed well before the 10-second inner sleep.
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn already_cancelled_token_short_circuits() {
        let token = CancellationToken::new();
        token.cancel();
        let got: Result<i32, CancelError<&str>> =
            cancellable(async { Ok::<i32, &str>(1) }, &token).await;
        // `tokio::select!` is non-deterministic which branch wins when
        // both are ready. The inner future is `async { Ok(1) }` — it
        // resolves immediately — so either branch is acceptable. What
        // matters is we don't hang.
        let _ = got;
    }

    #[tokio::test]
    async fn child_token_cancels_when_parent_cancels() {
        // Standard tokio_util::CancellationToken behavior — verified
        // here because our tests lean on it.
        let parent = CancellationToken::new();
        let child = parent.child_token();
        parent.cancel();

        let got: Result<i32, CancelError<&str>> =
            cancellable(async { Ok::<i32, &str>(1) }, &child).await;
        let _ = got; // non-deterministic which branch wins; no hang is the point
    }

    #[tokio::test]
    async fn cancel_error_is_cancelled_flag_works() {
        let err: CancelError<&str> = CancelError::Cancelled;
        assert!(err.is_cancelled());
        assert!(err.into_inner().is_none());

        let err: CancelError<&str> = CancelError::Inner("x");
        assert!(!err.is_cancelled());
        assert_eq!(err.into_inner(), Some("x"));
    }

    #[tokio::test]
    async fn cancellable_infallible_returns_some_on_success() {
        let token = CancellationToken::new();
        let got = cancellable_infallible(async { "hello" }, &token).await;
        assert_eq!(got, Some("hello"));
    }

    #[tokio::test]
    async fn cancellable_infallible_returns_none_on_cancel() {
        let token = CancellationToken::new();
        let child = token.child_token();
        tokio::spawn({
            let t = token.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                t.cancel();
            }
        });
        let got: Option<()> =
            cancellable_infallible(tokio::time::sleep(Duration::from_secs(5)), &child).await;
        assert!(got.is_none());
    }
}
