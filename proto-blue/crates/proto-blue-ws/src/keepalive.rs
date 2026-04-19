//! WebSocket keep-alive client with auto-reconnection and heartbeat.
//!
//! Wraps a [`WebSocketConnector`] with exponential-backoff reconnection
//! and a read-side heartbeat timeout. The same reconnection state machine
//! runs on native (`TungsteniteConnector`) and in the browser
//! (`GlooWsConnector`).

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, warn};

use crate::error::{WsError, is_reconnectable};
use crate::transport::{WebSocketConnector, WebSocketTransport, WsFrame};

/// Options for the WebSocket keep-alive client.
#[derive(Debug, Clone)]
pub struct WebSocketKeepAliveOpts {
    /// Maximum reconnect delay in seconds (default: 64).
    pub max_reconnect_seconds: u64,
    /// Heartbeat (ping) interval in milliseconds (default: 10000).
    pub heartbeat_interval_ms: u64,
}

impl Default for WebSocketKeepAliveOpts {
    fn default() -> Self {
        WebSocketKeepAliveOpts {
            max_reconnect_seconds: 64,
            heartbeat_interval_ms: 10_000,
        }
    }
}

/// WebSocket client with automatic reconnection and ping/pong heartbeat.
///
/// Connects via the supplied [`WebSocketConnector`], automatically
/// reconnects on network failure with exponential backoff, and uses a
/// read-side timeout (3 × heartbeat interval) to detect dead connections.
pub struct WebSocketKeepAlive {
    url: String,
    opts: WebSocketKeepAliveOpts,
    connector: Arc<dyn WebSocketConnector>,
    reconnects: u32,
    initial_setup: bool,
    transport: Option<Box<dyn WebSocketTransport>>,
}

impl WebSocketKeepAlive {
    /// Create a new keep-alive client using the crate's default connector.
    ///
    /// On native with `tungstenite` (default), this uses
    /// [`crate::transport::TungsteniteConnector`]. Without that feature
    /// callers must use [`Self::with_connector`].
    #[cfg(all(feature = "tungstenite", not(target_arch = "wasm32")))]
    pub fn new(url: impl Into<String>, opts: WebSocketKeepAliveOpts) -> Self {
        Self::with_connector(
            url,
            opts,
            Arc::new(crate::transport::TungsteniteConnector::new()),
        )
    }

    /// Create a new keep-alive client with a user-supplied connector.
    pub fn with_connector(
        url: impl Into<String>,
        opts: WebSocketKeepAliveOpts,
        connector: Arc<dyn WebSocketConnector>,
    ) -> Self {
        WebSocketKeepAlive {
            url: url.into(),
            opts,
            connector,
            reconnects: 0,
            initial_setup: true,
            transport: None,
        }
    }

    /// Connect to the WebSocket server.
    pub async fn connect(&mut self) -> Result<(), WsError> {
        let transport = self.connector.connect(&self.url).await?;
        self.transport = Some(transport);
        self.initial_setup = false;
        self.reconnects = 0;
        debug!("WebSocket connected to {}", self.url);
        Ok(())
    }

    /// Receive the next message, automatically reconnecting on failure.
    ///
    /// Returns `None` when the connection is cleanly closed.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, WsError> {
        loop {
            // Connect if not connected.
            if self.transport.is_none() {
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
                            self.reconnects += 1;
                            continue;
                        }
                        return Err(e);
                    }
                }
            }

            let transport = self.transport.as_mut().unwrap();

            let heartbeat_duration = Duration::from_millis(self.opts.heartbeat_interval_ms);

            match tokio::time::timeout(heartbeat_duration * 3, transport.recv()).await {
                Ok(Ok(Some(frame))) => match frame {
                    WsFrame::Binary(data) => return Ok(Some(data)),
                    WsFrame::Text(text) => return Ok(Some(text.into_bytes())),
                    // Heartbeats are informational — skip and keep reading.
                    WsFrame::Ping(_) | WsFrame::Pong(_) => continue,
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
                    // Heartbeat timeout — connection is dead.
                    warn!("Heartbeat timeout, reconnecting...");
                    self.disconnect().await;
                    self.reconnects += 1;
                    continue;
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
        // a scheduling decision, not a security-sensitive one.
        let jitter_ms: i64 = (rand::random::<f64>() * 1000.0) as i64 - 500;
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
        assert_eq!(delay, Duration::from_millis(1000));
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
    /// still not exceed the cap (we clamp final_ms to max_ms).
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
}
