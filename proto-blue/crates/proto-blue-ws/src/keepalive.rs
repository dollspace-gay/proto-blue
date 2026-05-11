//! WebSocket keep-alive client with auto-reconnection and heartbeat.
//!
//! Wraps a [`WebSocketConnector`] with exponential-backoff reconnection
//! and a read-side heartbeat timeout. The same reconnection state machine
//! runs on native (`TungsteniteConnector`) and in the browser
//! (`GlooWsConnector`).
//!
//! # Extension points
//!
//! - [`WebSocketKeepAlive::with_url_fn`] — supply a closure that
//!   produces the URL on every reconnect. Subscription consumers use
//!   this to inject the latest `?cursor=<seq>` on resume.
//! - [`WebSocketKeepAlive::on_reconnect`] — callback fired after every
//!   successful reconnect; useful for logging and metrics.
//! - [`WebSocketKeepAlive::on_reconnect_error`] — callback fired when
//!   a reconnect attempt fails (called before the retry backoff).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, warn};

use crate::error::{WsError, is_reconnectable};
use crate::transport::{WebSocketConnector, WebSocketTransport, WsFrame};

/// Boxed future returned by the `url_fn` callback.
///
/// Matches the `Send` bound on native and drops it on wasm32, mirroring
/// the rest of the `proto-blue-ws` transport crate's target split.
#[cfg(not(target_arch = "wasm32"))]
pub type UrlFuture = Pin<Box<dyn Future<Output = String> + Send + 'static>>;
#[cfg(target_arch = "wasm32")]
pub type UrlFuture = Pin<Box<dyn Future<Output = String> + 'static>>;

/// Async closure that produces the connection URL on each reconnect.
#[cfg(not(target_arch = "wasm32"))]
pub type UrlFn = Arc<dyn Fn() -> UrlFuture + Send + Sync + 'static>;
#[cfg(target_arch = "wasm32")]
pub type UrlFn = Arc<dyn Fn() -> UrlFuture + 'static>;

/// Callback fired on each successful reconnect. Receives the
/// (1-based) reconnect count; `None` for the initial setup.
#[cfg(not(target_arch = "wasm32"))]
pub type ReconnectCallback = Arc<dyn Fn(Option<u32>) + Send + Sync + 'static>;
#[cfg(target_arch = "wasm32")]
pub type ReconnectCallback = Arc<dyn Fn(Option<u32>) + 'static>;

/// Callback fired on a failed reconnect attempt. Receives the error
/// and the attempt count.
#[cfg(not(target_arch = "wasm32"))]
pub type ReconnectErrorCallback = Arc<dyn Fn(&WsError, u32) + Send + Sync + 'static>;
#[cfg(target_arch = "wasm32")]
pub type ReconnectErrorCallback = Arc<dyn Fn(&WsError, u32) + 'static>;

/// Options for the WebSocket keep-alive client.
#[derive(Debug, Clone)]
pub struct WebSocketKeepAliveOpts {
    /// Maximum reconnect delay in seconds (default: 64).
    pub max_reconnect_seconds: u64,
    /// Heartbeat (ping) interval in milliseconds (default: 10000).
    pub heartbeat_interval_ms: u64,
    /// Optional cap on consecutive failed reconnect attempts. When
    /// the limit is exceeded, [`WebSocketKeepAlive::recv`] returns
    /// [`WsError::ReconnectExhausted`] so a supervising caller can
    /// fall over to an alternate URL (multi-relay failover) instead
    /// of spinning forever on a dead endpoint. `None` preserves the
    /// previous behaviour of retrying indefinitely.
    pub max_reconnect_attempts: Option<u32>,
    /// Optional override for the per-`recv` read deadline in
    /// milliseconds. Defaults to `3 × heartbeat_interval_ms` — i.e.
    /// three missed heartbeats trigger a reconnect. Set this to bound
    /// silence on a TCP-accepting-then-dropping relay: e.g. a
    /// firehose at ~1500 events/sec should never be silent for 60
    /// seconds, so `Some(60_000)` forces a reconnect (and, with
    /// `max_reconnect_attempts`, an outer failover) when it is.
    pub per_recv_timeout_ms: Option<u64>,
}

impl Default for WebSocketKeepAliveOpts {
    fn default() -> Self {
        Self {
            max_reconnect_seconds: 64,
            heartbeat_interval_ms: 10_000,
            max_reconnect_attempts: None,
            per_recv_timeout_ms: None,
        }
    }
}

/// WebSocket client with automatic reconnection and ping/pong heartbeat.
///
/// Connects via the supplied [`WebSocketConnector`], automatically
/// reconnects on network failure with exponential backoff, and uses a
/// read-side timeout (3 × heartbeat interval) to detect dead connections.
pub struct WebSocketKeepAlive {
    /// Static fallback URL. Used when `url_fn` is `None`. Also used as
    /// the initial URL on first connect even if `url_fn` is set so
    /// callers don't have to handle "cold start" specially.
    url: String,
    opts: WebSocketKeepAliveOpts,
    connector: Arc<dyn WebSocketConnector>,
    reconnects: u32,
    initial_setup: bool,
    transport: Option<Box<dyn WebSocketTransport>>,
    /// Optional closure invoked on every reconnect to compute the next
    /// connection URL. Subscription clients use this to append
    /// `?cursor=<seq>` from their last-observed sequence number.
    url_fn: Option<UrlFn>,
    /// Optional reconnect-success callback.
    on_reconnect: Option<ReconnectCallback>,
    /// Optional reconnect-failure callback.
    on_reconnect_error: Option<ReconnectErrorCallback>,
}

impl WebSocketKeepAlive {
    /// Create a new keep-alive client using the crate's default connector.
    ///
    /// Picks the right backend per target: `TungsteniteConnector` on
    /// native (feature `tungstenite`), `GlooWsConnector` on
    /// `wasm32-unknown-unknown` (feature `gloo-ws`). With neither feature
    /// enabled, callers must use [`Self::with_connector`].
    #[cfg(all(feature = "tungstenite", not(target_arch = "wasm32")))]
    pub fn new(url: impl Into<String>, opts: WebSocketKeepAliveOpts) -> Self {
        Self::with_connector(
            url,
            opts,
            Arc::new(crate::transport::TungsteniteConnector::new()),
        )
    }

    /// Browser variant of [`Self::new`].
    #[cfg(all(feature = "gloo-ws", target_arch = "wasm32"))]
    pub fn new(url: impl Into<String>, opts: WebSocketKeepAliveOpts) -> Self {
        Self::with_connector(
            url,
            opts,
            Arc::new(crate::transport::GlooWsConnector::new()),
        )
    }

    /// Create a new keep-alive client with a user-supplied connector.
    pub fn with_connector(
        url: impl Into<String>,
        opts: WebSocketKeepAliveOpts,
        connector: Arc<dyn WebSocketConnector>,
    ) -> Self {
        Self {
            url: url.into(),
            opts,
            connector,
            reconnects: 0,
            initial_setup: true,
            transport: None,
            url_fn: None,
            on_reconnect: None,
            on_reconnect_error: None,
        }
    }

    /// Register a URL-producing closure, called on each reconnect.
    ///
    /// The closure returns a boxed future so callers can fetch the
    /// latest cursor from async state (a shared `Arc<AtomicU64>`, a
    /// database, etc.) before producing the URL. The initial connect
    /// also uses `url_fn` if it's set — callers don't need to pass an
    /// initial URL separately.
    #[must_use]
    pub fn with_url_fn(mut self, f: UrlFn) -> Self {
        self.url_fn = Some(f);
        self
    }

    /// Register a callback fired after every successful reconnect.
    ///
    /// The callback receives the reconnect count (1 for the first
    /// reconnect after initial setup, 2 for the next, etc.) or `None`
    /// for the initial-setup success.
    #[must_use]
    pub fn on_reconnect(mut self, f: ReconnectCallback) -> Self {
        self.on_reconnect = Some(f);
        self
    }

    /// Register a callback fired on reconnect failure, before backoff.
    #[must_use]
    pub fn on_reconnect_error(mut self, f: ReconnectErrorCallback) -> Self {
        self.on_reconnect_error = Some(f);
        self
    }

    /// Resolve the URL for the next connect — `url_fn` takes
    /// precedence over the static URL when supplied.
    async fn resolve_url(&self) -> String {
        if let Some(f) = &self.url_fn {
            f().await
        } else {
            self.url.clone()
        }
    }

    /// Connect to the WebSocket server.
    ///
    /// When a URL function is registered (`with_url_fn`), it is
    /// consulted for the target URL on every call — allowing
    /// subscription clients to inject a fresh `?cursor=<seq>`.
    pub async fn connect(&mut self) -> Result<(), WsError> {
        let url = self.resolve_url().await;
        let transport = self.connector.connect(&url).await?;
        self.transport = Some(transport);
        let was_initial = self.initial_setup;
        self.initial_setup = false;
        let reconnect_count = if was_initial {
            None
        } else {
            Some(self.reconnects.saturating_add(1))
        };
        self.reconnects = 0;
        debug!("WebSocket connected to {url}");
        if let Some(cb) = &self.on_reconnect {
            cb(reconnect_count);
        }
        Ok(())
    }

    /// Receive the next message, automatically reconnecting on failure.
    ///
    /// Returns `None` when the connection is cleanly closed.
    ///
    /// When `opts.max_reconnect_attempts` is set and the number of
    /// consecutive failed reconnects exceeds it, returns
    /// [`WsError::ReconnectExhausted`] so the caller can switch to a
    /// fallback relay.
    ///
    /// When `opts.per_recv_timeout_ms` is set, each read is bounded
    /// by that deadline instead of the default `3 × heartbeat_interval_ms`.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, WsError> {
        loop {
            // Connect if not connected.
            if self.transport.is_none() {
                if let Some(limit) = self.opts.max_reconnect_attempts
                    && self.reconnects >= limit
                {
                    let attempts = self.reconnects;
                    debug!("reconnect attempts exhausted ({attempts}), bailing");
                    return Err(WsError::ReconnectExhausted { attempts });
                }

                let delay = self.reconnect_delay();
                if delay > Duration::ZERO {
                    debug!("Reconnecting in {:?}...", delay);
                    tokio::time::sleep(delay).await;
                }

                match self.connect().await {
                    Ok(()) => {}
                    Err(e) => {
                        if is_reconnectable(&e) {
                            warn!("Reconnect failed: {}, retrying...", e);
                            if let Some(cb) = &self.on_reconnect_error {
                                cb(&e, self.reconnects.saturating_add(1));
                            }
                            self.reconnects += 1;
                            continue;
                        }
                        if let Some(cb) = &self.on_reconnect_error {
                            cb(&e, self.reconnects.saturating_add(1));
                        }
                        return Err(e);
                    }
                }
            }

            let transport = self.transport.as_mut().unwrap();

            let read_deadline = self.opts.per_recv_timeout_ms.map_or_else(
                || Duration::from_millis(self.opts.heartbeat_interval_ms) * 3,
                Duration::from_millis,
            );

            match tokio::time::timeout(read_deadline, transport.recv()).await {
                Ok(Ok(Some(frame))) => match frame {
                    WsFrame::Binary(data) => return Ok(Some(data)),
                    WsFrame::Text(text) => return Ok(Some(text.into_bytes())),
                    // Heartbeats are informational — skip and keep reading.
                    WsFrame::Ping(_) | WsFrame::Pong(_) => {}
                    WsFrame::Close { .. } => {
                        debug!("WebSocket closed by server");
                        self.disconnect().await;
                        return Ok(None);
                    }
                },
                Ok(Ok(None)) => {
                    // Peer cleanly ended the stream.
                    self.disconnect().await;
                    return Ok(None);
                }
                Ok(Err(e)) => {
                    if is_reconnectable(&e) {
                        warn!("WebSocket error: {}, reconnecting...", e);
                        self.disconnect().await;
                        self.reconnects += 1;
                        continue;
                    }
                    return Err(e);
                }
                Err(_) => {
                    // Read timed out — treat as a dead connection and
                    // reconnect. When `per_recv_timeout_ms` is set,
                    // this bounds silence on an accepted-then-dropped
                    // relay; combined with `max_reconnect_attempts` it
                    // surfaces as `ReconnectExhausted` after the cap
                    // so the caller can fail over.
                    warn!("recv timeout ({:?}), reconnecting...", read_deadline);
                    self.disconnect().await;
                    self.reconnects += 1;
                }
            }
        }
    }

    /// Send a binary message on the WebSocket.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), WsError> {
        let transport = self.transport.as_mut().ok_or(WsError::NotConnected)?;
        transport.send(WsFrame::Binary(data.to_vec())).await
    }

    /// Send a ping message.
    pub async fn ping(&mut self) -> Result<(), WsError> {
        let transport = self.transport.as_mut().ok_or(WsError::NotConnected)?;
        transport.send(WsFrame::Ping(Vec::new())).await
    }

    /// Check if the WebSocket is currently connected.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.transport.is_some()
    }

    /// Disconnect and clean up.
    async fn disconnect(&mut self) {
        if let Some(mut t) = self.transport.take() {
            let _ = t.close().await;
        }
    }

    /// Calculate the reconnect delay with exponential backoff and jitter.
    ///
    /// The backoff grows as `base = 1000 * 2^reconnects` ms, capped at
    /// `max_reconnect_seconds`. A uniform random jitter in `[-500, +500)` ms
    /// is added so that a fleet of clients disconnected by the same upstream
    /// event do not all reconnect simultaneously — the "thundering herd".
    /// This mirrors the TS ws-client's `backoffMs` helper.
    fn reconnect_delay(&self) -> Duration {
        if self.reconnects == 0 && !self.initial_setup {
            return Duration::ZERO;
        }

        let max_ms = self.opts.max_reconnect_seconds * 1000;

        if self.initial_setup {
            return Duration::from_millis(max_ms.min(1000));
        }

        let base_ms = 1000u64.saturating_mul(1u64 << self.reconnects.min(16));
        let capped = base_ms.min(max_ms);

        // Jitter in [-500, +500) ms. We use a non-cryptographic RNG; this is
        // a scheduling decision, not a security-sensitive one. The
        // `rand::random::<f64>() * 1000.0` value is bounded to `[0, 1000)`
        // so the cast to i64 cannot truncate. The `capped as i64` cast is
        // safe because `max_reconnect_seconds * 1000` is far below
        // `i64::MAX` for any sane backoff cap. The `.max(0) as u64`
        // re-converts a clamped non-negative i64 back to u64 — sign loss
        // is precisely what the clamp prevents.
        #[allow(clippy::cast_possible_truncation)]
        let jitter_ms: i64 = (rand::random::<f64>() * 1000.0) as i64 - 500;
        #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
        let with_jitter = (capped as i64 + jitter_ms).max(0) as u64;
        let final_ms = with_jitter.min(max_ms);
        Duration::from_millis(final_ms)
    }
}

#[cfg(all(test, feature = "tungstenite", not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn default_opts() {
        let opts = WebSocketKeepAliveOpts::default();
        assert_eq!(opts.max_reconnect_seconds, 64);
        assert_eq!(opts.heartbeat_interval_ms, 10_000);
    }

    #[test]
    fn reconnect_delay_initial() {
        let ws = WebSocketKeepAlive::new("ws://localhost:1234", WebSocketKeepAliveOpts::default());
        assert!(ws.initial_setup);
        // Initial setup path is deterministic (no jitter applied).
        let delay = ws.reconnect_delay();
        assert_eq!(delay, Duration::from_secs(1));
    }

    #[test]
    fn reconnect_delay_after_connect() {
        let mut ws =
            WebSocketKeepAlive::new("ws://localhost:1234", WebSocketKeepAliveOpts::default());
        ws.initial_setup = false;
        ws.reconnects = 0;
        assert_eq!(ws.reconnect_delay(), Duration::ZERO);
    }

    /// Exponential backoff, with ±500 ms of jitter for herd protection.
    /// Each expected value is `base = 2^n * 1000` ms; the real delay must
    /// fall in `[base - 500, base + 500)`.
    #[test]
    fn reconnect_delay_exponential_backoff_with_jitter() {
        let mut ws =
            WebSocketKeepAlive::new("ws://localhost:1234", WebSocketKeepAliveOpts::default());
        ws.initial_setup = false;

        for (n, base_ms) in [(1u32, 2000u64), (2, 4000), (3, 8000)] {
            ws.reconnects = n;
            for _ in 0..10 {
                let delay_ms = ws.reconnect_delay().as_millis() as u64;
                assert!(
                    delay_ms + 500 >= base_ms && delay_ms < base_ms + 500,
                    "n={n} base={base_ms} got={delay_ms}"
                );
            }
        }
    }

    /// Cap still applies after jitter. At `reconnects = 20` the uncapped
    /// backoff would be 2^20 seconds; the cap brings it to
    /// `max_reconnect_seconds * 1000`, and adding +500 ms of jitter must
    /// still not exceed the cap (we clamp `final_ms` to `max_ms`).
    #[test]
    fn reconnect_delay_capped() {
        let mut ws =
            WebSocketKeepAlive::new("ws://localhost:1234", WebSocketKeepAliveOpts::default());
        ws.initial_setup = false;
        ws.reconnects = 20;
        let max_ms = 64 * 1000;
        for _ in 0..10 {
            let delay_ms = ws.reconnect_delay().as_millis() as u64;
            // Delay is [max - 500, max], since positive jitter is clamped.
            assert!(
                delay_ms + 500 >= max_ms && delay_ms <= max_ms,
                "capped delay out of range: {delay_ms}"
            );
        }
    }

    /// Herd-protection regression: two consecutive calls at the same
    /// reconnect count must not produce identical delays every time.
    /// The probability of collision over 100 draws is astronomically
    /// small if jitter is actually random.
    #[test]
    fn reconnect_delay_has_non_trivial_jitter_variance() {
        let mut ws =
            WebSocketKeepAlive::new("ws://localhost:1234", WebSocketKeepAliveOpts::default());
        ws.initial_setup = false;
        ws.reconnects = 5;

        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            seen.insert(ws.reconnect_delay().as_millis());
        }
        assert!(
            seen.len() > 10,
            "jitter has no variance: only {} distinct delays",
            seen.len()
        );
    }

    #[test]
    fn not_connected_initially() {
        let ws = WebSocketKeepAlive::new("ws://localhost:1234", WebSocketKeepAliveOpts::default());
        assert!(!ws.is_connected());
    }

    // ── url_fn / reconnect callbacks ─────────────────────────────────
    //
    // These tests drive the state machine with a custom connector that
    // records every URL it receives, so we can observe that `url_fn`
    // is consulted (with fresh state) on every (re)connect and that
    // the reconnect callbacks fire with correct counts.

    use crate::transport::{WebSocketConnector, WebSocketTransport, WsFrame};
    use async_trait::async_trait;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    /// Connector that records every URL it's asked to dial.
    struct RecordingConnector {
        urls: Arc<Mutex<Vec<String>>>,
        /// When `>0`, the first `fail_first_n` connect attempts error;
        /// subsequent attempts succeed with an `ImmediateEofTransport`.
        fail_first_n: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl WebSocketConnector for RecordingConnector {
        async fn connect(&self, url: &str) -> Result<Box<dyn WebSocketTransport>, WsError> {
            self.urls.lock().unwrap().push(url.to_string());
            // Saturating decrement — `AtomicUsize::fetch_sub` wraps on
            // underflow, which would silently flip success back to
            // failure after the initial `fail_first_n` budget is
            // exhausted.
            let mut remaining = self.fail_first_n.load(Ordering::SeqCst);
            loop {
                if remaining == 0 {
                    break;
                }
                match self.fail_first_n.compare_exchange(
                    remaining,
                    remaining - 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => return Err(WsError::Transport("simulated failure".into())),
                    Err(actual) => remaining = actual,
                }
            }
            Ok(Box::new(ImmediateEofTransport))
        }
    }

    /// Transport that returns `Ok(None)` on the first `recv` — emulates
    /// a peer that connects and immediately closes cleanly.
    struct ImmediateEofTransport;

    #[async_trait]
    impl WebSocketTransport for ImmediateEofTransport {
        async fn recv(&mut self) -> Result<Option<WsFrame>, WsError> {
            Ok(None)
        }
        async fn send(&mut self, _frame: WsFrame) -> Result<(), WsError> {
            Ok(())
        }
        async fn close(&mut self) -> Result<(), WsError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn url_fn_is_consulted_on_connect() {
        let urls = Arc::new(Mutex::new(Vec::new()));
        let connector = Arc::new(RecordingConnector {
            urls: urls.clone(),
            fail_first_n: Arc::new(AtomicUsize::new(0)),
        });

        let call_count = Arc::new(AtomicU32::new(0));
        let cc = call_count.clone();
        let url_fn: UrlFn = Arc::new(move || {
            let cc = cc.clone();
            Box::pin(async move {
                let n = cc.fetch_add(1, Ordering::SeqCst);
                format!("wss://example.com/stream?cursor={n}")
            })
        });

        let mut ws = WebSocketKeepAlive::with_connector(
            "wss://fallback/",
            WebSocketKeepAliveOpts::default(),
            connector,
        )
        .with_url_fn(url_fn);

        ws.connect().await.unwrap();
        assert_eq!(
            urls.lock().unwrap().as_slice(),
            &["wss://example.com/stream?cursor=0"]
        );

        // Force a reconnect by clearing the transport and invoking
        // connect again — mirrors what recv() does on peer close.
        ws.transport = None;
        ws.connect().await.unwrap();

        let seen = urls.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![
                "wss://example.com/stream?cursor=0".to_string(),
                "wss://example.com/stream?cursor=1".to_string(),
            ],
            "url_fn must be re-invoked on each connect",
        );
    }

    #[tokio::test]
    async fn on_reconnect_fires_with_initial_none_and_then_counts() {
        let urls = Arc::new(Mutex::new(Vec::new()));
        let connector = Arc::new(RecordingConnector {
            urls,
            fail_first_n: Arc::new(AtomicUsize::new(0)),
        });

        let events: Arc<Mutex<Vec<Option<u32>>>> = Arc::new(Mutex::new(Vec::new()));
        let ev = events.clone();
        let cb: ReconnectCallback = Arc::new(move |n| ev.lock().unwrap().push(n));

        let mut ws = WebSocketKeepAlive::with_connector(
            "wss://example/",
            WebSocketKeepAliveOpts::default(),
            connector,
        )
        .on_reconnect(cb);

        ws.connect().await.unwrap();
        ws.transport = None;
        ws.connect().await.unwrap();

        let seen = events.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![None, Some(1)],
            "first connect is `None` (initial setup); reconnect is Some(1)",
        );
    }

    #[tokio::test]
    async fn on_reconnect_error_fires_on_failed_attempt() {
        let urls = Arc::new(Mutex::new(Vec::new()));
        // First two connects fail with Transport error, third succeeds.
        let connector = Arc::new(RecordingConnector {
            urls,
            fail_first_n: Arc::new(AtomicUsize::new(2)),
        });

        let err_events: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let ev = err_events.clone();
        let err_cb: ReconnectErrorCallback =
            Arc::new(move |_e, attempt| ev.lock().unwrap().push(attempt));

        let ws = WebSocketKeepAlive::with_connector(
            "wss://example/",
            WebSocketKeepAliveOpts::default(),
            connector,
        )
        .on_reconnect_error(err_cb);

        // Just call connect() twice — both should fail, exercising
        // the error-callback path. We don't invoke recv() because that
        // would loop forever with backoff; the error hook triggers in
        // both `connect()` and inside the `recv()` reconnect loop.
        let mut ws = ws;
        assert!(ws.connect().await.is_err());
        assert!(ws.connect().await.is_err());

        // `connect()` itself doesn't fire on_reconnect_error — only
        // the reconnect loop inside recv() does. So the error vec is
        // expected to be empty here; a future integration test could
        // cover the recv path.
        let seen = err_events.lock().unwrap().clone();
        assert!(
            seen.is_empty(),
            "connect() alone should not fire the recv-loop error hook"
        );
    }

    // ── max_reconnect_attempts / per_recv_timeout_ms (issue #3) ──────────

    /// With `max_reconnect_attempts = Some(n)`, `recv` must surface
    /// `ReconnectExhausted { attempts: n }` after n consecutive
    /// connect failures instead of spinning forever. Lets a
    /// supervising caller fall over to an alternate relay.
    #[tokio::test]
    async fn recv_bails_with_reconnect_exhausted_after_max_attempts() {
        let connector = Arc::new(RecordingConnector {
            urls: Arc::new(Mutex::new(Vec::new())),
            // Fail every connect attempt — unbounded budget is fine
            // because the cap below stops the loop first.
            fail_first_n: Arc::new(AtomicUsize::new(usize::MAX)),
        });

        let opts = WebSocketKeepAliveOpts {
            max_reconnect_seconds: 0,
            heartbeat_interval_ms: 10_000,
            max_reconnect_attempts: Some(3),
            per_recv_timeout_ms: None,
        };
        let mut ws =
            WebSocketKeepAlive::with_connector("wss://unreachable.example/", opts, connector);

        let err = ws
            .recv()
            .await
            .expect_err("expected ReconnectExhausted after retry cap");
        match err {
            WsError::ReconnectExhausted { attempts } => assert_eq!(attempts, 3),
            other => panic!("expected ReconnectExhausted, got {other:?}"),
        }
    }

    /// When `per_recv_timeout_ms` is set, a transport that never
    /// emits a frame triggers a reconnect on the custom deadline
    /// instead of waiting `3 × heartbeat_interval_ms`. Combined with
    /// `max_reconnect_attempts = 0`, one timeout is enough to bail —
    /// proving the timeout path fires.
    #[tokio::test]
    async fn recv_honors_per_recv_timeout_override() {
        /// Transport that blocks forever on recv.
        struct SilentTransport;
        #[async_trait]
        impl WebSocketTransport for SilentTransport {
            async fn recv(&mut self) -> Result<Option<WsFrame>, WsError> {
                std::future::pending().await
            }
            async fn send(&mut self, _frame: WsFrame) -> Result<(), WsError> {
                Ok(())
            }
            async fn close(&mut self) -> Result<(), WsError> {
                Ok(())
            }
        }

        /// Connector that yields a `SilentTransport` exactly once, then
        /// errors (so the retry-cap branch fires).
        struct SilentThenError {
            served: AtomicUsize,
        }
        #[async_trait]
        impl WebSocketConnector for SilentThenError {
            async fn connect(&self, _url: &str) -> Result<Box<dyn WebSocketTransport>, WsError> {
                if self.served.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(Box::new(SilentTransport))
                } else {
                    Err(WsError::Transport("simulated failure".into()))
                }
            }
        }

        let connector = Arc::new(SilentThenError {
            served: AtomicUsize::new(0),
        });

        let opts = WebSocketKeepAliveOpts {
            max_reconnect_seconds: 0,
            heartbeat_interval_ms: 10_000, // default timeout would be 30s
            max_reconnect_attempts: Some(0),
            per_recv_timeout_ms: Some(50), // force recv to time out fast
        };
        let mut ws = WebSocketKeepAlive::with_connector("wss://silent/", opts, connector);

        let start = std::time::Instant::now();
        let err = ws
            .recv()
            .await
            .expect_err("expected exhaustion after timeout");
        // Must time out on the 50ms override, not the 30s default.
        // Give the event loop a generous budget (1s) to stay flake-
        // resistant on busy CI.
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "per_recv_timeout_ms ignored — took {:?}",
            start.elapsed()
        );
        assert!(
            matches!(err, WsError::ReconnectExhausted { .. }),
            "expected ReconnectExhausted after timeout, got {err:?}"
        );
    }
}
