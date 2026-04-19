//! AT Protocol WebSocket client with auto-reconnection.
//!
//! Provides a WebSocket client that automatically reconnects on connection
//! failure with exponential backoff, and uses a read-side heartbeat
//! timeout to detect dead connections. HTTP transport is abstracted behind
//! [`transport::WebSocketConnector`] so the same reconnection logic drives
//! `tokio-tungstenite` on native and the browser's native `WebSocket` on
//! `wasm32-unknown-unknown`.

pub mod error;
pub mod frame;
pub mod keepalive;
pub mod transport;

pub use error::{CloseCode, DisconnectError, WsError};
pub use frame::{ErrorFrame, Frame, FrameError, MessageFrame, OP_ERROR, OP_MESSAGE};
pub use keepalive::{WebSocketKeepAlive, WebSocketKeepAliveOpts};
pub use transport::{WebSocketConnector, WebSocketTransport, WsFrame};

#[cfg(all(feature = "tungstenite", not(target_arch = "wasm32")))]
pub use transport::TungsteniteConnector;

#[cfg(all(feature = "gloo-ws", target_arch = "wasm32"))]
pub use transport::GlooWsConnector;
