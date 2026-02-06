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
    pub fn from_raw(code: u16) -> Option<Self> {
        match code {
            1000 => Some(CloseCode::Normal),
            1006 => Some(CloseCode::Abnormal),
            1008 => Some(CloseCode::Policy),
            _ => None,
        }
    }
}

impl From<CloseCode> for u16 {
    fn from(code: CloseCode) -> u16 {
        code as u16
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
    pub fn new(ws_code: CloseCode, xrpc_code: Option<String>) -> Self {
        DisconnectError { ws_code, xrpc_code }
    }
}

/// Errors that can occur during WebSocket operations.
#[derive(Debug, thiserror::Error)]
pub enum WsError {
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("Disconnect: {0}")]
    Disconnect(#[from] DisconnectError),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Not connected")]
    NotConnected,

    #[error("{0}")]
    Other(String),
}

/// Check if an error is likely a network error that we should reconnect for.
pub fn is_reconnectable(err: &WsError) -> bool {
    match err {
        WsError::WebSocket(e) => {
            matches!(
                e,
                tokio_tungstenite::tungstenite::Error::ConnectionClosed
                    | tokio_tungstenite::tungstenite::Error::AlreadyClosed
                    | tokio_tungstenite::tungstenite::Error::Io(_)
            )
        }
        WsError::ConnectionClosed => true,
        WsError::Disconnect(_) => false,
        WsError::NotConnected => false,
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
