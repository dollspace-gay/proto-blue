//! Transport-agnostic WebSocket abstraction.
//!
//! Mirrors `@atproto/xrpc-server`'s separation between "what bytes go in
//! and out of a WebSocket" (the [`WebSocketTransport`] trait here) and
//! "how do we dial a new connection" (the [`WebSocketConnector`] trait).
//!
//! Two connectors ship with the crate:
//!
//! - [`TungsteniteConnector`] (feature `tungstenite`, default on native) —
//!   the pre-existing `tokio-tungstenite` implementation.
//! - `GlooWsConnector` (feature `gloo-ws`, wasm32 only) — backed by the
//!   browser's native `WebSocket` via `gloo-net`.
//!
//! Higher-level code — [`crate::keepalive::WebSocketKeepAlive`] — drives
//! reconnection + heartbeat on top of whichever connector is configured,
//! so the identical resume / backoff logic runs on native and in the
//! browser.

use async_trait::async_trait;

use crate::error::WsError;

/// A single WebSocket frame.
///
/// The variants cover everything the firehose protocol cares about —
/// binary message frames (what subscription streams actually use), text,
/// heartbeats, and a clean close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsFrame {
    /// Binary payload.
    Binary(Vec<u8>),
    /// Text payload.
    Text(String),
    /// Ping with application-supplied data.
    Ping(Vec<u8>),
    /// Pong with application-supplied data.
    Pong(Vec<u8>),
    /// Clean close with optional code + reason.
    Close {
        code: Option<u16>,
        reason: Option<String>,
    },
}

/// An active WebSocket connection.
///
/// `recv` returns `None` when the peer cleanly closes (the `Close` frame
/// is consumed internally). `send` accepts any [`WsFrame`] variant; `close`
/// performs a clean shutdown.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait WebSocketTransport: Send + Sync {
    async fn recv(&mut self) -> Result<Option<WsFrame>, WsError>;
    async fn send(&mut self, frame: WsFrame) -> Result<(), WsError>;
    async fn close(&mut self) -> Result<(), WsError>;
}

/// An active WebSocket connection. Wasm variant with `?Send` futures.
#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait WebSocketTransport {
    async fn recv(&mut self) -> Result<Option<WsFrame>, WsError>;
    async fn send(&mut self, frame: WsFrame) -> Result<(), WsError>;
    async fn close(&mut self) -> Result<(), WsError>;
}

/// A dialer for WebSocket connections.
///
/// Allows the keep-alive / reconnect loop to request a fresh transport on
/// demand without knowing which backend is wired up.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait WebSocketConnector: Send + Sync {
    async fn connect(&self, url: &str) -> Result<Box<dyn WebSocketTransport>, WsError>;
}

/// A dialer for WebSocket connections. Wasm variant with `?Send` futures.
#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait WebSocketConnector {
    async fn connect(&self, url: &str) -> Result<Box<dyn WebSocketTransport>, WsError>;
}

// ── tungstenite backend ─────────────────────────────────────────────────

#[cfg(all(feature = "tungstenite", not(target_arch = "wasm32")))]
mod tungstenite_impl {
    use std::sync::Arc;

    use futures::{SinkExt, StreamExt};
    use tokio::net::TcpStream;
    use tokio_tungstenite::tungstenite::Message;
    #[cfg(feature = "rustls-tls")]
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

    use super::{WebSocketConnector, WebSocketTransport, WsFrame};
    use crate::error::WsError;
    use async_trait::async_trait;

    type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

    /// `tokio-tungstenite`-backed connector. Native only.
    ///
    /// Dials over the default `tokio-tungstenite` TLS stack
    /// (`native-tls` on system roots) unless a custom
    /// [`rustls::ClientConfig`] was installed via
    /// [`Self::with_rustls_config`] — typically to add internal CA
    /// roots for self-hosted atproto deployments.
    #[derive(Debug, Default, Clone)]
    pub struct TungsteniteConnector {
        /// Optional pre-built rustls client config. When `Some`,
        /// `connect` routes through
        /// `tokio_tungstenite::connect_async_tls_with_config` with
        /// `Connector::Rustls(config)` so the caller's roots /
        /// verifier take effect.
        #[cfg(feature = "rustls-tls")]
        rustls_config: Option<Arc<rustls::ClientConfig>>,
        // Keep the non-rustls build zero-sized. `Arc` is just to
        // placate the cfg'd field above without another branch.
        #[cfg(not(feature = "rustls-tls"))]
        _marker: std::marker::PhantomData<Arc<()>>,
    }

    impl TungsteniteConnector {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Install a custom [`rustls::ClientConfig`]. When set, every
        /// subsequent `connect()` routes through
        /// `tokio_tungstenite::connect_async_tls_with_config` using
        /// this config — letting operators add internal CA roots
        /// (common in self-hosted atproto deployments) or pin specific
        /// certificates without touching the system trust store.
        ///
        /// Requires the `rustls-tls` feature.
        #[cfg(feature = "rustls-tls")]
        #[must_use]
        pub fn with_rustls_config(mut self, config: Arc<rustls::ClientConfig>) -> Self {
            self.rustls_config = Some(config);
            self
        }
    }

    struct TungsteniteTransport {
        stream: WsStream,
    }

    fn frame_to_message(frame: WsFrame) -> Message {
        match frame {
            WsFrame::Binary(data) => Message::Binary(data.into()),
            WsFrame::Text(text) => Message::Text(text.into()),
            WsFrame::Ping(data) => Message::Ping(data.into()),
            WsFrame::Pong(data) => Message::Pong(data.into()),
            WsFrame::Close { code, reason } => {
                // A `None` code means "close with no payload" which
                // tungstenite represents as `Message::Close(None)`.
                let cf = code.map(|c| tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code: c.into(),
                    reason: reason.unwrap_or_default().into(),
                });
                Message::Close(cf)
            }
        }
    }

    fn message_to_frame(msg: Message) -> Option<WsFrame> {
        Some(match msg {
            Message::Binary(data) => WsFrame::Binary(data.to_vec()),
            Message::Text(text) => WsFrame::Text(text.to_string()),
            Message::Ping(data) => WsFrame::Ping(data.to_vec()),
            Message::Pong(data) => WsFrame::Pong(data.to_vec()),
            Message::Close(Some(cf)) => WsFrame::Close {
                code: Some(cf.code.into()),
                reason: Some(cf.reason.to_string()),
            },
            Message::Close(None) => WsFrame::Close {
                code: None,
                reason: None,
            },
            // `Message::Frame` is a raw frame — tungstenite emits it only
            // when the client configures `accept_unmasked_frames`. We
            // don't, so this branch is unreachable in practice. Treating
            // it as "keep reading" (None = skip) is the safe default.
            Message::Frame(_) => return None,
        })
    }

    #[async_trait]
    impl WebSocketConnector for TungsteniteConnector {
        async fn connect(&self, url: &str) -> Result<Box<dyn WebSocketTransport>, WsError> {
            #[cfg(feature = "rustls-tls")]
            if let Some(config) = &self.rustls_config {
                use tokio_tungstenite::Connector;
                use tokio_tungstenite::connect_async_tls_with_config;

                let request = url.into_client_request().map_err(WsError::WebSocket)?;
                let connector = Connector::Rustls(config.clone());
                let (stream, _) = connect_async_tls_with_config(
                    request,
                    /*config=*/ None,
                    /*disable_nagle=*/ false,
                    Some(connector),
                )
                .await?;
                return Ok(Box::new(TungsteniteTransport { stream }));
            }
            let (stream, _) = connect_async(url).await?;
            Ok(Box::new(TungsteniteTransport { stream }))
        }
    }

    #[async_trait]
    impl WebSocketTransport for TungsteniteTransport {
        async fn recv(&mut self) -> Result<Option<WsFrame>, WsError> {
            loop {
                match self.stream.next().await {
                    Some(Ok(msg)) => {
                        let is_close = matches!(msg, Message::Close(_));
                        if let Some(frame) = message_to_frame(msg) {
                            return Ok(Some(frame));
                        } else if is_close {
                            // Should be unreachable since Close always
                            // maps to Some(WsFrame::Close{..}), but be
                            // defensive in case the mapping ever changes.
                            return Ok(None);
                        }
                        // Skipped frame (raw `Message::Frame`) — keep reading.
                    }
                    Some(Err(e)) => return Err(WsError::WebSocket(e)),
                    None => return Ok(None),
                }
            }
        }

        async fn send(&mut self, frame: WsFrame) -> Result<(), WsError> {
            self.stream
                .send(frame_to_message(frame))
                .await
                .map_err(WsError::WebSocket)
        }

        async fn close(&mut self) -> Result<(), WsError> {
            self.stream.close(None).await.map_err(WsError::WebSocket)
        }
    }
}

#[cfg(all(feature = "tungstenite", not(target_arch = "wasm32")))]
pub use tungstenite_impl::TungsteniteConnector;

// ── gloo-net (browser) backend ─────────────────────────────────────────

#[cfg(all(feature = "gloo-ws", target_arch = "wasm32"))]
mod gloo_impl {
    use futures::{SinkExt, StreamExt};
    use gloo_net::websocket::{Message, futures::WebSocket};

    use super::{WebSocketConnector, WebSocketTransport, WsFrame};
    use crate::error::WsError;
    use async_trait::async_trait;

    /// Browser `WebSocket`-backed connector. Wasm32 only.
    #[derive(Debug, Default, Clone)]
    pub struct GlooWsConnector;

    impl GlooWsConnector {
        pub fn new() -> Self {
            Self
        }
    }

    struct GlooTransport {
        // `gloo_net::websocket::futures::WebSocket::close` takes `self`
        // by value, so we store it as `Option` and take it out on close.
        // After close, further operations return `NotConnected`.
        ws: Option<WebSocket>,
    }

    impl GlooTransport {
        fn ws_mut(&mut self) -> Result<&mut WebSocket, WsError> {
            self.ws.as_mut().ok_or(WsError::NotConnected)
        }
    }

    #[async_trait(?Send)]
    impl WebSocketConnector for GlooWsConnector {
        async fn connect(&self, url: &str) -> Result<Box<dyn WebSocketTransport>, WsError> {
            let ws = WebSocket::open(url).map_err(|e| WsError::Transport(e.to_string()))?;
            Ok(Box::new(GlooTransport { ws: Some(ws) }))
        }
    }

    #[async_trait(?Send)]
    impl WebSocketTransport for GlooTransport {
        async fn recv(&mut self) -> Result<Option<WsFrame>, WsError> {
            let ws = self.ws_mut()?;
            match ws.next().await {
                Some(Ok(Message::Bytes(b))) => Ok(Some(WsFrame::Binary(b))),
                Some(Ok(Message::Text(t))) => Ok(Some(WsFrame::Text(t))),
                Some(Err(e)) => Err(WsError::Transport(e.to_string())),
                None => Ok(None),
            }
        }

        async fn send(&mut self, frame: WsFrame) -> Result<(), WsError> {
            let msg = match frame {
                WsFrame::Binary(b) => Message::Bytes(b),
                WsFrame::Text(t) => Message::Text(t),
                // The browser WebSocket API doesn't expose ping/pong
                // construction (the browser handles those transparently)
                // or send-side close-frame details. For the firehose
                // client we only ever need to send binary payloads; the
                // other variants are a no-op on wasm.
                WsFrame::Ping(_) | WsFrame::Pong(_) | WsFrame::Close { .. } => return Ok(()),
            };
            let ws = self.ws_mut()?;
            ws.send(msg)
                .await
                .map_err(|e| WsError::Transport(e.to_string()))
        }

        async fn close(&mut self) -> Result<(), WsError> {
            if let Some(ws) = self.ws.take() {
                ws.close(None, None)
                    .map_err(|e| WsError::Transport(e.to_string()))?;
            }
            Ok(())
        }
    }
}

#[cfg(all(feature = "gloo-ws", target_arch = "wasm32"))]
pub use gloo_impl::GlooWsConnector;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_frame_variants_round_trip_via_debug() {
        let f = WsFrame::Binary(vec![1, 2, 3]);
        assert!(format!("{f:?}").contains("Binary"));
        let f = WsFrame::Text("hello".into());
        assert!(format!("{f:?}").contains("Text"));
        let f = WsFrame::Close {
            code: Some(1000),
            reason: Some("bye".into()),
        };
        assert!(format!("{f:?}").contains("1000"));
    }

    /// `with_rustls_config` installs a caller-supplied
    /// `rustls::ClientConfig` on the connector. We can't drive a full
    /// TLS handshake from a unit test cheaply, but we can at least
    /// assert the builder wires the config through without panicking
    /// and that the connector is `Clone` + `Debug` with it set.
    #[cfg(all(
        feature = "tungstenite",
        feature = "rustls-tls",
        not(target_arch = "wasm32")
    ))]
    #[test]
    fn tungstenite_connector_with_rustls_config_builds() {
        use std::sync::Arc;

        // Empty root store — enough to construct a valid
        // ClientConfig; we don't dial anything with it.
        let roots = rustls::RootCertStore::empty();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TungsteniteConnector::new().with_rustls_config(Arc::new(config));
        let _clone = connector.clone();
        assert!(format!("{connector:?}").contains("TungsteniteConnector"));
    }
}
