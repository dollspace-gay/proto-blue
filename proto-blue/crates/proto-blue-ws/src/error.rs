//! WebSocket error types.

/// WebSocket close codes per RFC 6455 Section 7.4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CloseCode {
    Normal = 1000,
    Abnormal = 1006,
    Policy = 1008,
}

impl CloseCode {
    /// Convert from a raw u16 close code.
    #[must_use]
    pub const fn from_raw(code: u16) -> Option<Self> {
        match code {
            1000 => Some(Self::Normal),
            1006 => Some(Self::Abnormal),
            1008 => Some(Self::Policy),
            _ => None,
        }
    }
}

impl From<CloseCode> for u16 {
    fn from(code: CloseCode) -> Self {
        code as Self
    }
}

/// Error indicating a clean disconnect was requested.
#[derive(Debug, thiserror::Error)]
#[error("Disconnected with code {ws_code:?}")]
pub struct DisconnectError {
    /// WebSocket close code to send.
    pub ws_code: CloseCode,
    /// Optional XRPC error code.
    pub xrpc_code: Option<String>,
}

impl DisconnectError {
    /// Create a new disconnect error.
    #[must_use]
    pub const fn new(ws_code: CloseCode, xrpc_code: Option<String>) -> Self {
        Self { ws_code, xrpc_code }
    }
}

/// Errors that can occur during WebSocket operations.
#[derive(Debug, thiserror::Error)]
pub enum WsError {
    /// Tungstenite (native) transport error.
    #[cfg(all(feature = "tungstenite", not(target_arch = "wasm32")))]
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    /// Transport-level error from a non-tungstenite backend (e.g. the
    /// browser `WebSocket` on wasm). Carries a backend-provided message;
    /// treated as reconnectable by the keep-alive loop.
    #[error("transport error: {0}")]
    Transport(String),

    #[error("Disconnect: {0}")]
    Disconnect(#[from] DisconnectError),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Not connected")]
    NotConnected,

    /// `WebSocketKeepAlive` exhausted its configured
    /// `max_reconnect_attempts` bound. The outer supervisor can match
    /// on this variant to switch to a fallback relay instead of
    /// continuing the retry loop.
    #[error("reconnect attempts exhausted after {attempts} tries")]
    ReconnectExhausted { attempts: u32 },

    #[error("{0}")]
    Other(String),
}

/// Check if an error is likely a network error that we should reconnect for.
pub const fn is_reconnectable(err: &WsError) -> bool {
    match err {
        #[cfg(all(feature = "tungstenite", not(target_arch = "wasm32")))]
        WsError::WebSocket(e) => {
            matches!(
                e,
                tokio_tungstenite::tungstenite::Error::ConnectionClosed
                    | tokio_tungstenite::tungstenite::Error::AlreadyClosed
                    | tokio_tungstenite::tungstenite::Error::Io(_)
            )
        }
        WsError::Transport(_) => true,
        WsError::ConnectionClosed => true,
        WsError::Disconnect(_) => false,
        WsError::NotConnected => false,
        // `ReconnectExhausted` is terminal by construction — the
        // caller asked us to stop retrying. Returning `false` prevents
        // the keep-alive loop from re-entering itself on this error.
        WsError::ReconnectExhausted { .. } => false,
        WsError::Other(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_code_from_raw() {
        assert_eq!(CloseCode::from_raw(1000), Some(CloseCode::Normal));
        assert_eq!(CloseCode::from_raw(1006), Some(CloseCode::Abnormal));
        assert_eq!(CloseCode::from_raw(1008), Some(CloseCode::Policy));
        assert_eq!(CloseCode::from_raw(9999), None);
    }

    #[test]
    fn close_code_to_u16() {
        assert_eq!(u16::from(CloseCode::Normal), 1000);
        assert_eq!(u16::from(CloseCode::Abnormal), 1006);
        assert_eq!(u16::from(CloseCode::Policy), 1008);
    }

    #[test]
    fn disconnect_error_display() {
        let err = DisconnectError::new(CloseCode::Policy, None);
        assert!(err.to_string().contains("Policy"));
    }

    #[test]
    fn reconnectable_errors() {
        assert!(!is_reconnectable(&WsError::NotConnected));
        assert!(is_reconnectable(&WsError::ConnectionClosed));
        assert!(!is_reconnectable(&WsError::Disconnect(
            DisconnectError::new(CloseCode::Policy, None)
        )));
    }
}
