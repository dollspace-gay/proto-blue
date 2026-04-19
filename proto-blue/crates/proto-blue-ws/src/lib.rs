//! AT Protocol WebSocket client with auto-reconnection.
//!
//! Provides a WebSocket client that automatically reconnects on connection
//! failure with exponential backoff, and uses ping/pong heartbeat to detect
//! dead connections.

pub mod error;
pub mod frame;
pub mod keepalive;

pub use error::{CloseCode, DisconnectError, WsError};
pub use frame::{ErrorFrame, Frame, FrameError, MessageFrame, OP_ERROR, OP_MESSAGE};
pub use keepalive::{WebSocketKeepAlive, WebSocketKeepAliveOpts};
