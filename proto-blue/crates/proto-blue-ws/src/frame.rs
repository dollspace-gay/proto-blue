//! Streaming-XRPC (subscribe*) CBOR frame encoding and decoding.
//!
//! atproto subscription streams (e.g. `com.atproto.sync.subscribeRepos`) send
//! each event as a pair of back-to-back DAG-CBOR values on the wire:
//!
//! 1. A **header** map describing the op (`1` for a regular message, `-1`
//!    for an error) and, for messages, an optional `t` discriminator (e.g.
//!    `"#commit"`, `"#identity"`, `"#account"`).
//! 2. A **body** map whose shape depends on the op: an arbitrary lexicon
//!    payload for messages, or `{error, message}` for errors.
//!
//! Reference: `packages/xrpc-server/src/stream/frames.ts` in the TS SDK.
//!
//! # Examples
//!
//! ```
//! use proto_blue_ws::{Frame, MessageFrame};
//! use proto_blue_lex_data::LexValue;
//! use std::collections::BTreeMap;
//!
//! let mut body = BTreeMap::new();
//! body.insert("seq".to_string(), LexValue::Integer(42));
//! let frame = Frame::Message(MessageFrame {
//!     r#type: Some("#commit".to_string()),
//!     body: LexValue::Map(body),
//! });
//!
//! let bytes = frame.encode().unwrap();
//! let roundtripped = Frame::decode(&bytes).unwrap();
//! assert_eq!(frame, roundtripped);
//! ```

use std::collections::BTreeMap;

use proto_blue_lex_cbor::{decode_all, encode};
use proto_blue_lex_data::LexValue;

/// Op code for a message frame. Must match the TS `FrameType.Message`.
pub const OP_MESSAGE: i64 = 1;
/// Op code for an error frame. Must match the TS `FrameType.Error`.
pub const OP_ERROR: i64 = -1;

/// Errors that can occur while parsing or emitting a streaming frame.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Underlying DAG-CBOR encode failed.
    #[error("CBOR encode error: {0}")]
    Encode(String),

    /// Underlying DAG-CBOR decode failed.
    #[error("CBOR decode error: {0}")]
    Decode(String),

    /// A frame must contain exactly two CBOR values (header + body).
    #[error("frame must contain exactly 2 CBOR values, got {0}")]
    WrongValueCount(usize),

    /// Header map is missing the required `op` key or it's not an integer.
    #[error("frame header missing or invalid `op` field")]
    MissingOp,

    /// `op` field had an unknown value.
    #[error("unknown frame op: {0}")]
    UnknownOp(i64),

    /// Header map has an unexpected shape (e.g. not a map, bad `t` type).
    #[error("invalid frame header: {0}")]
    InvalidHeader(String),

    /// Error-frame body was not the expected `{error, message?}` shape.
    #[error("invalid error frame body: {0}")]
    InvalidErrorBody(String),
}

impl From<proto_blue_lex_cbor::CborError> for FrameError {
    fn from(e: proto_blue_lex_cbor::CborError) -> Self {
        Self::Decode(e.to_string())
    }
}

/// A decoded subscription frame — either a message or an error.
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    /// A successful message frame carrying a lexicon-typed payload.
    Message(MessageFrame),
    /// An error frame terminating the stream (or describing a transient
    /// failure).
    Error(ErrorFrame),
}

/// A `op = 1` frame.
#[derive(Debug, Clone, PartialEq)]
pub struct MessageFrame {
    /// Optional type discriminator (`t` in the CBOR header). For subscription
    /// lexicons this identifies the union variant, e.g. `"#commit"`.
    pub r#type: Option<String>,
    /// Arbitrary lexicon-typed body.
    pub body: LexValue,
}

/// A `op = -1` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorFrame {
    /// Machine-readable error code (e.g. `"FutureCursor"`).
    pub error: String,
    /// Optional human-readable message.
    pub message: Option<String>,
}

impl Frame {
    /// Encode this frame as the two-CBOR-value wire format.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let (header, body) = match self {
            Self::Message(m) => (build_message_header(m.r#type.as_deref()), m.body.clone()),
            Self::Error(e) => (build_error_header(), build_error_body(e)),
        };

        let mut out = encode(&header).map_err(|e| FrameError::Encode(e.to_string()))?;
        let body_bytes = encode(&body).map_err(|e| FrameError::Encode(e.to_string()))?;
        out.extend_from_slice(&body_bytes);
        Ok(out)
    }

    /// Decode a two-CBOR-value frame from bytes.
    ///
    /// Strictly requires exactly two CBOR values — any trailing bytes after
    /// the body are rejected, matching the TS reference (`Too many CBOR
    /// data items in frame`). Non-canonical CBOR is rejected by the
    /// underlying `proto-blue-lex-cbor` decoder.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        let values = decode_all(bytes)?;
        if values.len() != 2 {
            return Err(FrameError::WrongValueCount(values.len()));
        }
        let mut iter = values.into_iter();
        let header = iter.next().unwrap();
        let body = iter.next().unwrap();

        let op = read_op(&header)?;
        match op {
            OP_MESSAGE => {
                let r#type = read_optional_string_field(&header, "t")?;
                Ok(Self::Message(MessageFrame { r#type, body }))
            }
            OP_ERROR => {
                let frame = parse_error_body(&body)?;
                Ok(Self::Error(frame))
            }
            other => Err(FrameError::UnknownOp(other)),
        }
    }
}

// ── header and body helpers ─────────────────────────────────────────────

fn build_message_header(t: Option<&str>) -> LexValue {
    let mut m = BTreeMap::new();
    m.insert("op".to_string(), LexValue::Integer(OP_MESSAGE));
    if let Some(ty) = t {
        m.insert("t".to_string(), LexValue::String(ty.to_string()));
    }
    LexValue::Map(m)
}

fn build_error_header() -> LexValue {
    let mut m = BTreeMap::new();
    m.insert("op".to_string(), LexValue::Integer(OP_ERROR));
    LexValue::Map(m)
}

fn build_error_body(e: &ErrorFrame) -> LexValue {
    let mut m = BTreeMap::new();
    m.insert("error".to_string(), LexValue::String(e.error.clone()));
    if let Some(msg) = &e.message {
        m.insert("message".to_string(), LexValue::String(msg.clone()));
    }
    LexValue::Map(m)
}

fn read_op(header: &LexValue) -> Result<i64, FrameError> {
    let map = header
        .as_map()
        .ok_or_else(|| FrameError::InvalidHeader("header is not a CBOR map".to_string()))?;
    match map.get("op") {
        Some(LexValue::Integer(n)) => Ok(*n),
        Some(_) | None => Err(FrameError::MissingOp),
    }
}

fn read_optional_string_field(header: &LexValue, key: &str) -> Result<Option<String>, FrameError> {
    let map = header
        .as_map()
        .ok_or_else(|| FrameError::InvalidHeader("header is not a CBOR map".to_string()))?;
    match map.get(key) {
        None => Ok(None),
        Some(LexValue::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(FrameError::InvalidHeader(format!(
            "header field `{key}` must be a string"
        ))),
    }
}

fn parse_error_body(body: &LexValue) -> Result<ErrorFrame, FrameError> {
    let map = body
        .as_map()
        .ok_or_else(|| FrameError::InvalidErrorBody("body is not a CBOR map".to_string()))?;
    let error = match map.get("error") {
        Some(LexValue::String(s)) => s.clone(),
        _ => {
            return Err(FrameError::InvalidErrorBody(
                "missing or non-string `error` field".to_string(),
            ));
        }
    };
    let message = match map.get("message") {
        None => None,
        Some(LexValue::String(s)) => Some(s.clone()),
        Some(_) => {
            return Err(FrameError::InvalidErrorBody(
                "`message` field must be a string if present".to_string(),
            ));
        }
    };
    Ok(ErrorFrame { error, message })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_body() -> LexValue {
        let mut m = BTreeMap::new();
        m.insert("seq".to_string(), LexValue::Integer(42));
        m.insert("repo".to_string(), LexValue::String("did:plc:abc".into()));
        LexValue::Map(m)
    }

    // ── round-trips ──

    #[test]
    fn message_frame_with_type_roundtrips() {
        let frame = Frame::Message(MessageFrame {
            r#type: Some("#commit".to_string()),
            body: make_body(),
        });
        let bytes = frame.encode().unwrap();
        let back = Frame::decode(&bytes).unwrap();
        assert_eq!(frame, back);
    }

    #[test]
    fn message_frame_without_type_roundtrips() {
        let frame = Frame::Message(MessageFrame {
            r#type: None,
            body: LexValue::String("hi".into()),
        });
        let bytes = frame.encode().unwrap();
        let back = Frame::decode(&bytes).unwrap();
        assert_eq!(frame, back);
    }

    #[test]
    fn error_frame_with_message_roundtrips() {
        let frame = Frame::Error(ErrorFrame {
            error: "FutureCursor".to_string(),
            message: Some("cursor too far in the future".to_string()),
        });
        let bytes = frame.encode().unwrap();
        let back = Frame::decode(&bytes).unwrap();
        assert_eq!(frame, back);
    }

    #[test]
    fn error_frame_without_message_roundtrips() {
        let frame = Frame::Error(ErrorFrame {
            error: "ConsumerTooSlow".to_string(),
            message: None,
        });
        let bytes = frame.encode().unwrap();
        let back = Frame::decode(&bytes).unwrap();
        assert_eq!(frame, back);
    }

    // ── adversarial decode cases ──

    #[test]
    fn rejects_empty_input() {
        assert!(matches!(
            Frame::decode(&[]),
            Err(FrameError::WrongValueCount(0))
        ));
    }

    #[test]
    fn rejects_single_cbor_value() {
        // Just the header with no body.
        let only_header = encode(&build_message_header(Some("#commit"))).unwrap();
        assert!(matches!(
            Frame::decode(&only_header),
            Err(FrameError::WrongValueCount(1))
        ));
    }

    #[test]
    fn rejects_three_cbor_values() {
        // Header + body + garbage — TS rejects this as "Too many CBOR data
        // items in frame"; we mirror that.
        let mut out = encode(&build_message_header(None)).unwrap();
        out.extend_from_slice(&encode(&LexValue::Integer(1)).unwrap());
        out.extend_from_slice(&encode(&LexValue::Integer(2)).unwrap());
        assert!(matches!(
            Frame::decode(&out),
            Err(FrameError::WrongValueCount(3))
        ));
    }

    #[test]
    fn rejects_unknown_op() {
        let mut header = BTreeMap::new();
        header.insert("op".to_string(), LexValue::Integer(2));
        let mut bytes = encode(&LexValue::Map(header)).unwrap();
        bytes.extend_from_slice(&encode(&LexValue::Null).unwrap());
        assert!(matches!(
            Frame::decode(&bytes),
            Err(FrameError::UnknownOp(2))
        ));
    }

    #[test]
    fn rejects_non_integer_op() {
        let mut header = BTreeMap::new();
        header.insert("op".to_string(), LexValue::String("one".into()));
        let mut bytes = encode(&LexValue::Map(header)).unwrap();
        bytes.extend_from_slice(&encode(&LexValue::Null).unwrap());
        assert!(matches!(Frame::decode(&bytes), Err(FrameError::MissingOp)));
    }

    #[test]
    fn rejects_missing_op() {
        let mut header = BTreeMap::new();
        header.insert("t".to_string(), LexValue::String("#commit".into()));
        let mut bytes = encode(&LexValue::Map(header)).unwrap();
        bytes.extend_from_slice(&encode(&LexValue::Null).unwrap());
        assert!(matches!(Frame::decode(&bytes), Err(FrameError::MissingOp)));
    }

    #[test]
    fn rejects_non_map_header() {
        let mut bytes = encode(&LexValue::Integer(1)).unwrap();
        bytes.extend_from_slice(&encode(&LexValue::Null).unwrap());
        assert!(matches!(
            Frame::decode(&bytes),
            Err(FrameError::InvalidHeader(_))
        ));
    }

    #[test]
    fn rejects_non_string_type_field() {
        let mut header = BTreeMap::new();
        header.insert("op".to_string(), LexValue::Integer(OP_MESSAGE));
        header.insert("t".to_string(), LexValue::Integer(42));
        let mut bytes = encode(&LexValue::Map(header)).unwrap();
        bytes.extend_from_slice(&encode(&LexValue::Null).unwrap());
        assert!(matches!(
            Frame::decode(&bytes),
            Err(FrameError::InvalidHeader(_))
        ));
    }

    #[test]
    fn rejects_error_body_without_error_field() {
        let header = build_error_header();
        let body = LexValue::Map(BTreeMap::new());
        let mut bytes = encode(&header).unwrap();
        bytes.extend_from_slice(&encode(&body).unwrap());
        assert!(matches!(
            Frame::decode(&bytes),
            Err(FrameError::InvalidErrorBody(_))
        ));
    }

    #[test]
    fn rejects_error_body_with_non_string_message() {
        let header = build_error_header();
        let mut body = BTreeMap::new();
        body.insert("error".to_string(), LexValue::String("X".into()));
        body.insert("message".to_string(), LexValue::Integer(1));
        let mut bytes = encode(&header).unwrap();
        bytes.extend_from_slice(&encode(&LexValue::Map(body)).unwrap());
        assert!(matches!(
            Frame::decode(&bytes),
            Err(FrameError::InvalidErrorBody(_))
        ));
    }

    #[test]
    fn rejects_garbage_bytes() {
        // Not valid CBOR at all.
        let garbage = vec![0xff, 0xff, 0xff, 0xff];
        assert!(Frame::decode(&garbage).is_err());
    }

    // ── wire-compatibility: header bytes match hand-crafted CBOR ──

    /// The message-frame header `{op: 1}` must serialize to exactly three
    /// bytes: `map(1) 'op' 1` = `a1 62 6f 70 01`. This is a direct wire-
    /// format check — if this changes, the frame is not binary-compatible
    /// with TS consumers.
    #[test]
    fn message_header_without_type_serializes_to_exact_bytes() {
        let bytes = encode(&build_message_header(None)).unwrap();
        assert_eq!(bytes, vec![0xa1, 0x62, b'o', b'p', 0x01]);
    }

    /// Same, but for the error header. CBOR -1 = 0x20.
    #[test]
    fn error_header_serializes_to_exact_bytes() {
        let bytes = encode(&build_error_header()).unwrap();
        assert_eq!(bytes, vec![0xa1, 0x62, b'o', b'p', 0x20]);
    }
}
