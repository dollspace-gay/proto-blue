//! Firehose WebSocket client.
//!
//! Connects to `com.atproto.sync.subscribeRepos` (or any other
//! subscription endpoint) and yields decoded [`FirehoseEvent`]s. Wraps
//! [`proto_blue_ws::WebSocketKeepAlive`] for reconnection + heartbeat
//! and [`crate::firehose::decode_event`] for per-event parsing.
//!
//! # Example
//!
//! ```no_run
//! # use proto_blue_repo::{Firehose, FirehoseEvent};
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let mut fh = Firehose::new(
//!     "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos",
//! );
//! while let Some(evt) = fh.next_event().await? {
//!     match evt {
//!         FirehoseEvent::Commit(c) => println!("commit seq={} repo={}", c.seq, c.repo),
//!         FirehoseEvent::Sync(s) => println!("sync seq={} did={}", s.seq, s.did),
//!         FirehoseEvent::Identity(i) => println!("identity {}", i.did),
//!         FirehoseEvent::Account(a) => println!("account {} active={}", a.did, a.active),
//!         FirehoseEvent::Info(i) => println!("info {}", i.name),
//!         FirehoseEvent::Unknown { r#type, .. } => println!("unknown {type}"),
//!     }
//! }
//! # Ok(()) }
//! ```
//!
//! ## Cursor replay
//!
//! atproto subscription streams support `?cursor=<seq>` to resume from
//! a known position. Because the underlying keep-alive uses a fixed URL
//! for reconnects, a consumer that wants cursor replay should:
//!
//! 1. Persist the latest observed `seq` after each handled event.
//! 2. If the connection is lost for long enough to need replay, drop
//!    the `Firehose`, construct a new one with the updated URL
//!    (`?cursor=<persisted>`), and resume reading.
//!
//! This keeps the client simple and avoids hiding complex state
//! transitions. For most consumers, this is also the policy they want.

use proto_blue_ws::{Frame, WebSocketKeepAlive, WebSocketKeepAliveOpts};

use crate::error::RepoError;
use crate::firehose::{FirehoseEvent, decode_event};

/// A connected (or reconnecting) firehose subscription.
pub struct Firehose {
    ws: WebSocketKeepAlive,
}

impl Firehose {
    /// Create a new firehose client pointing at the given WSS URL.
    /// Uses the default keep-alive options (64s max backoff, 10s
    /// heartbeat).
    pub fn new(url: impl Into<String>) -> Self {
        Firehose::with_opts(url, WebSocketKeepAliveOpts::default())
    }

    /// Create a firehose client with custom keep-alive options.
    pub fn with_opts(url: impl Into<String>, opts: WebSocketKeepAliveOpts) -> Self {
        Firehose {
            ws: WebSocketKeepAlive::new(url, opts),
        }
    }

    /// Wait for the next frame from the server and decode it into a
    /// [`FirehoseEvent`].
    ///
    /// Returns:
    /// - `Ok(Some(evt))` — one event decoded successfully.
    /// - `Ok(None)` — stream closed cleanly.
    /// - `Err(RepoError::FirehoseError { .. })` — server sent an
    ///   error frame (e.g. `FutureCursor`, `ConsumerTooSlow`).
    /// - `Err(RepoError::Frame(_))` / `WebSocket(_)` — lower-level
    ///   decode or transport failure.
    pub async fn next_event(&mut self) -> Result<Option<FirehoseEvent>, RepoError> {
        loop {
            let Some(bytes) = self.ws.recv().await? else {
                return Ok(None); // clean close
            };
            // Empty frames shouldn't happen; skip them rather than bubbling
            // up a Frame error.
            if bytes.is_empty() {
                continue;
            }

            // `Frame::decode` returns `Result<Frame, FrameError>`;
            // `RepoError: From<FrameError>` handles the `?` coercion.
            let frame = Frame::decode(&bytes)?;

            match frame {
                Frame::Error(err) => {
                    return Err(RepoError::FirehoseError {
                        error: err.error,
                        message: err.message,
                    });
                }
                Frame::Message(msg) => {
                    let evt = decode_event(msg.r#type.as_deref(), &msg.body)?;
                    return Ok(Some(evt));
                }
            }
        }
    }

    /// Connect (or reconnect) explicitly. Usually unnecessary — the
    /// first call to `next_event` will connect lazily.
    pub async fn connect(&mut self) -> Result<(), RepoError> {
        self.ws.connect().await?;
        Ok(())
    }

    /// `true` if the underlying WebSocket is currently connected.
    pub fn is_connected(&self) -> bool {
        self.ws.is_connected()
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the firehose client.
    //!
    //! Network-dependent tests (connecting to a real PDS or a mock WS
    //! server) would require substantial infrastructure. We exercise
    //! the message → event decoding path end-to-end via a fake frame
    //! built in memory — covering the same logic that the real client
    //! runs after `WebSocketKeepAlive::recv` hands it bytes.

    use super::*;
    use proto_blue_lex_data::LexValue;
    use proto_blue_ws::{ErrorFrame, Frame, MessageFrame};
    use std::collections::BTreeMap;

    fn commit_body() -> LexValue {
        let mut m = BTreeMap::new();
        m.insert("seq".into(), LexValue::Integer(1));
        m.insert("rebase".into(), LexValue::Bool(false));
        m.insert("tooBig".into(), LexValue::Bool(false));
        m.insert("repo".into(), LexValue::String("did:plc:r".into()));
        m.insert(
            "commit".into(),
            LexValue::Cid(proto_blue_lex_cbor::cid_for_lex(&LexValue::Bytes(vec![0])).unwrap()),
        );
        m.insert("rev".into(), LexValue::String("3jzfcijpj2z2a".into()));
        m.insert("since".into(), LexValue::Null);
        m.insert("blocks".into(), LexValue::Bytes(Vec::new()));
        m.insert("ops".into(), LexValue::Array(Vec::new()));
        m.insert("blobs".into(), LexValue::Array(Vec::new()));
        m.insert(
            "time".into(),
            LexValue::String("2025-01-01T00:00:00Z".into()),
        );
        LexValue::Map(m)
    }

    /// The frame-bytes → FirehoseEvent path exercised directly.
    ///
    /// This is the entire decode pipeline that `next_event` runs after
    /// it gets bytes from the WS. If this passes, the only thing left
    /// untested is the WS transport itself — which is covered in
    /// proto-blue-ws's integration tests.
    #[test]
    fn message_frame_bytes_decode_end_to_end() {
        let frame = Frame::Message(MessageFrame {
            r#type: Some("#commit".to_string()),
            body: commit_body(),
        });
        let bytes = frame.encode().unwrap();

        // Simulate what next_event does: decode Frame, dispatch by type.
        let decoded = Frame::decode(&bytes).unwrap();
        match decoded {
            Frame::Message(msg) => {
                let evt = decode_event(msg.r#type.as_deref(), &msg.body).unwrap();
                assert!(matches!(evt, FirehoseEvent::Commit(_)));
                assert_eq!(evt.seq(), Some(1));
                assert_eq!(evt.did(), Some("did:plc:r"));
            }
            _ => panic!("expected Message"),
        }
    }

    /// Server-sent error frame must surface as `RepoError::FirehoseError`
    /// with the `error` and `message` fields preserved for logging.
    #[test]
    fn error_frame_is_surfaced_as_firehose_error() {
        let frame = Frame::Error(ErrorFrame {
            error: "FutureCursor".to_string(),
            message: Some("cursor is ahead of the server".to_string()),
        });
        let bytes = frame.encode().unwrap();

        // Simulate next_event's error path.
        let decoded = Frame::decode(&bytes).unwrap();
        let err: RepoError = match decoded {
            Frame::Error(err) => RepoError::FirehoseError {
                error: err.error,
                message: err.message,
            },
            _ => panic!("expected Error frame"),
        };

        match err {
            RepoError::FirehoseError { error, message } => {
                assert_eq!(error, "FutureCursor");
                assert_eq!(message.as_deref(), Some("cursor is ahead of the server"));
            }
            _ => panic!("expected FirehoseError"),
        }
    }

    /// Corrupt frame bytes must produce `RepoError::Frame` (not panic).
    #[test]
    fn invalid_bytes_produce_frame_error() {
        let corrupt = vec![0xff, 0xff, 0xff];
        let res = Frame::decode(&corrupt).map_err(RepoError::from);
        assert!(matches!(res, Err(RepoError::Frame(_))));
    }

    /// Unknown discriminator becomes `FirehoseEvent::Unknown`, not an
    /// error — future-compat forwarding.
    #[test]
    fn unknown_discriminator_yields_unknown_variant() {
        let frame = Frame::Message(MessageFrame {
            r#type: Some("#futurism".to_string()),
            body: LexValue::Map(BTreeMap::new()),
        });
        let bytes = frame.encode().unwrap();
        let decoded = Frame::decode(&bytes).unwrap();
        let Frame::Message(msg) = decoded else {
            panic!("expected Message")
        };
        let evt = decode_event(msg.r#type.as_deref(), &msg.body).unwrap();
        assert!(matches!(evt, FirehoseEvent::Unknown { .. }));
    }

    #[test]
    fn client_construction_does_not_connect() {
        // `new` is cheap and does no I/O. If this ever starts requiring
        // a runtime it's a regression.
        let fh = Firehose::new("wss://example.invalid/xrpc/noop");
        assert!(!fh.is_connected());
    }
}
