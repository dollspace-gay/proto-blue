//! WebSocket keep-alive client with auto-reconnection and heartbeat.

use std::time::Duration;

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use tracing::{debug, warn};

use crate::error::{WsError, is_reconnectable};

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

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
/// Connects to a WebSocket URL, automatically reconnects on network failure
/// with exponential backoff, and uses ping/pong to detect dead connections.
pub struct WebSocketKeepAlive {
    url: String,
    opts: WebSocketKeepAliveOpts,
    reconnects: u32,
    initial_setup: bool,
    writer: Option<SplitSink<WsStream, Message>>,
    reader: Option<SplitStream<WsStream>>,
}

impl WebSocketKeepAlive {
    /// Create a new WebSocket keep-alive client.
    pub fn new(url: impl Into<String>, opts: WebSocketKeepAliveOpts) -> Self {
        WebSocketKeepAlive {
            url: url.into(),
            opts,
            reconnects: 0,
            initial_setup: true,
            writer: None,
            reader: None,
        }
    }

    /// Connect to the WebSocket server.
    pub async fn connect(&mut self) -> Result<(), WsError> {
        let (ws_stream, _) = connect_async(&self.url).await?;
        let (writer, reader) = ws_stream.split();
        self.writer = Some(writer);
        self.reader = Some(reader);
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
            // Connect if not connected
            if self.reader.is_none() {
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

            let reader = self.reader.as_mut().unwrap();

            // Set up heartbeat timeout
            let heartbeat_duration = Duration::from_millis(self.opts.heartbeat_interval_ms);

            match tokio::time::timeout(heartbeat_duration * 3, reader.next()).await {
                Ok(Some(Ok(msg))) => {
                    match msg {
                        Message::Binary(data) => return Ok(Some(data.to_vec())),
                        Message::Text(text) => return Ok(Some(text.as_bytes().to_vec())),
                        Message::Ping(_) => {
                            // Pong is handled automatically by tungstenite
                            continue;
                        }
                        Message::Pong(_) => continue,
                        Message::Close(_) => {
                            debug!("WebSocket closed by server");
                            self.disconnect().await;
                            return Ok(None);
                        }
                        Message::Frame(_) => continue,
                    }
                }
                Ok(Some(Err(e))) => {
                    let ws_err = WsError::WebSocket(e);
                    if is_reconnectable(&ws_err) {
                        warn!("WebSocket error: {}, reconnecting...", ws_err);
                        self.disconnect().await;
                        self.reconnects += 1;
                        continue;
                    }
                    return Err(ws_err);
                }
                Ok(None) => {
                    // Stream ended
                    self.disconnect().await;
                    return Ok(None);
                }
                Err(_) => {
                    // Heartbeat timeout — connection is dead
                    warn!("Heartbeat timeout, reconnecting...");
                    self.disconnect().await;
                    self.reconnects += 1;
                    continue;
                }
            }
        }
    }

    /// Send a message on the WebSocket.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), WsError> {
        let writer = self.writer.as_mut().ok_or(WsError::NotConnected)?;
        writer
            .send(Message::Binary(data.to_vec().into()))
            .await
            .map_err(WsError::WebSocket)
    }

    /// Send a ping message.
    pub async fn ping(&mut self) -> Result<(), WsError> {
        let writer = self.writer.as_mut().ok_or(WsError::NotConnected)?;
        writer
            .send(Message::Ping(vec![].into()))
            .await
            .map_err(WsError::WebSocket)
    }

    /// Check if the WebSocket is currently connected.
    pub fn is_connected(&self) -> bool {
        self.reader.is_some()
    }

    /// Disconnect and clean up.
    async fn disconnect(&mut self) {
        if let Some(mut writer) = self.writer.take() {
            let _ = writer.close().await;
        }
        self.reader = None;
    }

    /// Calculate the reconnect delay with exponential backoff and jitter.
    fn reconnect_delay(&self) -> Duration {
        if self.reconnects == 0 && !self.initial_setup {
            return Duration::ZERO;
        }

        let max_ms = self.opts.max_reconnect_seconds * 1000;

        if self.initial_setup {
            return Duration::from_millis(max_ms.min(1000));
        }

        let base_ms = 1000u64.saturating_mul(1u64 << self.reconnects.min(16));
        let ms = base_ms.min(max_ms);
        Duration::from_millis(ms)
    }
}

#[cfg(test)]
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

    #[test]
    fn reconnect_delay_exponential_backoff() {
        let mut ws =
            WebSocketKeepAlive::new("ws://localhost:1234", WebSocketKeepAliveOpts::default());
        ws.initial_setup = false;

        ws.reconnects = 1;
        assert_eq!(ws.reconnect_delay(), Duration::from_millis(2000));

        ws.reconnects = 2;
        assert_eq!(ws.reconnect_delay(), Duration::from_millis(4000));

        ws.reconnects = 3;
        assert_eq!(ws.reconnect_delay(), Duration::from_millis(8000));
    }

    #[test]
    fn reconnect_delay_capped() {
        let mut ws =
            WebSocketKeepAlive::new("ws://localhost:1234", WebSocketKeepAliveOpts::default());
        ws.initial_setup = false;
        ws.reconnects = 20;
        let delay = ws.reconnect_delay();
        let max_ms = 64 * 1000;
        assert_eq!(delay, Duration::from_millis(max_ms));
    }

    #[test]
    fn not_connected_initially() {
        let ws = WebSocketKeepAlive::new("ws://localhost:1234", WebSocketKeepAliveOpts::default());
        assert!(!ws.is_connected());
    }
}
