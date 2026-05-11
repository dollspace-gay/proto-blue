//! Firehose event decoding.
//!
//! atproto's `com.atproto.sync.subscribeRepos` subscription emits CBOR
//! framed events on a WebSocket. Frame layout is handled by
//! `proto-blue-ws`; this module turns the decoded frame body into a
//! typed Rust enum.
//!
//! Five message variants plus an error frame (handled at the WS layer):
//!
//! | Discriminator | Variant                |
//! |---------------|------------------------|
//! | `#commit`     | [`FirehoseEvent::Commit`]   |
//! | `#sync`       | [`FirehoseEvent::Sync`]     |
//! | `#identity`   | [`FirehoseEvent::Identity`] |
//! | `#account`    | [`FirehoseEvent::Account`]  |
//! | `#info`       | [`FirehoseEvent::Info`]     |
//!
//! Per the lexicon, both commit and sync events embed a CAR file in the
//! `blocks` field. Decoding that CAR and verifying the commit is the
//! caller's responsibility — use [`crate::verify_repo_car`] or
//! [`crate::verify_diff_car`] once you have the bytes.

use proto_blue_lex_data::{Cid, LexValue};
use std::collections::BTreeMap;

use crate::error::RepoError;

/// A decoded subscription event.
///
/// `Unknown` captures any future discriminator we don't yet recognize,
/// so a firehose consumer can log & skip rather than crashing on a
/// schema extension.
#[derive(Debug, Clone, PartialEq)]
pub enum FirehoseEvent {
    Commit(CommitEvent),
    Sync(SyncEvent),
    Identity(IdentityEvent),
    Account(AccountEvent),
    Info(InfoEvent),
    /// A frame whose `t` discriminator we don't handle. The raw body is
    /// preserved so callers can choose to decode it themselves.
    Unknown {
        r#type: String,
        body: LexValue,
    },
}

impl FirehoseEvent {
    /// Sequence number, if present. Every event except some `Info`
    /// variants carries one.
    #[must_use]
    pub const fn seq(&self) -> Option<i64> {
        match self {
            Self::Commit(e) => Some(e.seq),
            Self::Sync(e) => Some(e.seq),
            Self::Identity(e) => Some(e.seq),
            Self::Account(e) => Some(e.seq),
            Self::Info(_) | Self::Unknown { .. } => None,
        }
    }

    /// DID of the repo this event is about, if applicable.
    #[must_use]
    pub fn did(&self) -> Option<&str> {
        match self {
            Self::Commit(e) => Some(&e.repo),
            Self::Sync(e) => Some(&e.did),
            Self::Identity(e) => Some(&e.did),
            Self::Account(e) => Some(&e.did),
            Self::Info(_) | Self::Unknown { .. } => None,
        }
    }
}

/// A `#commit` event: repo state changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitEvent {
    pub seq: i64,
    pub rebase: bool,
    pub too_big: bool,
    /// DID of the repo (spec calls this `repo`, not `did`).
    pub repo: String,
    /// CID of the signed commit object.
    pub commit: Cid,
    /// TID of this commit's revision.
    pub rev: String,
    /// TID of the previous commit from this repo, or `None` for genesis.
    pub since: Option<String>,
    /// CAR file bytes containing the commit block plus MST/record diff.
    pub blocks: Vec<u8>,
    /// Per-record mutations described by this commit.
    pub ops: Vec<RepoOp>,
    /// Deprecated; typically empty.
    pub blobs: Vec<Cid>,
    /// Optional prior-MST-root CID for inductive verification.
    pub prev_data: Option<Cid>,
    /// ISO-8601 broadcast time.
    pub time: String,
}

/// A `#sync` event: full-state recovery message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncEvent {
    pub seq: i64,
    pub did: String,
    pub blocks: Vec<u8>,
    pub rev: String,
    pub time: String,
}

/// An `#identity` event: handle / DID doc changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityEvent {
    pub seq: i64,
    pub did: String,
    pub time: String,
    pub handle: Option<String>,
}

/// An `#account` event: account activation / takedown / etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountEvent {
    pub seq: i64,
    pub did: String,
    pub time: String,
    pub active: bool,
    pub status: Option<String>,
}

/// An `#info` event: server status / cursor warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoEvent {
    pub name: String,
    pub message: Option<String>,
}

/// A single mutation inside a `#commit` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoOp {
    pub action: RepoOpAction,
    pub path: String,
    /// New record CID for create/update; `None` for delete.
    pub cid: Option<Cid>,
    /// Previous record CID for update/delete (optional, for inductive).
    pub prev: Option<Cid>,
}

/// The action of a [`RepoOp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoOpAction {
    Create,
    Update,
    Delete,
}

impl RepoOpAction {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

/// Decode a firehose event from its frame header `t` discriminator and
/// CBOR-decoded body.
///
/// Unknown discriminators map to `FirehoseEvent::Unknown` rather than an
/// error — this keeps consumers from falling over when the server ships
/// a new event type ahead of the client.
///
/// Missing / wrongly-typed *required* fields inside a known variant DO
/// produce an error — silent acceptance there would hide real bugs.
pub fn decode_event(frame_type: Option<&str>, body: &LexValue) -> Result<FirehoseEvent, RepoError> {
    let map = body
        .as_map()
        .ok_or_else(|| RepoError::InvalidCommit("firehose body is not a map".into()))?;

    match frame_type {
        Some("#commit") => Ok(FirehoseEvent::Commit(decode_commit(map)?)),
        Some("#sync") => Ok(FirehoseEvent::Sync(decode_sync(map)?)),
        Some("#identity") => Ok(FirehoseEvent::Identity(decode_identity(map)?)),
        Some("#account") => Ok(FirehoseEvent::Account(decode_account(map)?)),
        Some("#info") => Ok(FirehoseEvent::Info(decode_info(map)?)),
        Some(other) => Ok(FirehoseEvent::Unknown {
            r#type: other.to_string(),
            body: body.clone(),
        }),
        None => Ok(FirehoseEvent::Unknown {
            r#type: String::new(),
            body: body.clone(),
        }),
    }
}

// ── per-variant decoders ─────────────────────────────────────────────

fn decode_commit(map: &BTreeMap<String, LexValue>) -> Result<CommitEvent, RepoError> {
    Ok(CommitEvent {
        seq: integer_field(map, "seq")?,
        rebase: boolean_field(map, "rebase")?,
        too_big: boolean_field(map, "tooBig")?,
        repo: string_field(map, "repo")?,
        commit: cid_field(map, "commit")?,
        rev: string_field(map, "rev")?,
        since: nullable_string_field(map, "since")?,
        blocks: bytes_field(map, "blocks")?,
        ops: decode_ops(map.get("ops"))?,
        blobs: decode_cid_array(map.get("blobs"))?,
        prev_data: optional_cid_field(map, "prevData"),
        time: string_field(map, "time")?,
    })
}

fn decode_sync(map: &BTreeMap<String, LexValue>) -> Result<SyncEvent, RepoError> {
    Ok(SyncEvent {
        seq: integer_field(map, "seq")?,
        did: string_field(map, "did")?,
        blocks: bytes_field(map, "blocks")?,
        rev: string_field(map, "rev")?,
        time: string_field(map, "time")?,
    })
}

fn decode_identity(map: &BTreeMap<String, LexValue>) -> Result<IdentityEvent, RepoError> {
    Ok(IdentityEvent {
        seq: integer_field(map, "seq")?,
        did: string_field(map, "did")?,
        time: string_field(map, "time")?,
        handle: optional_string_field(map, "handle"),
    })
}

fn decode_account(map: &BTreeMap<String, LexValue>) -> Result<AccountEvent, RepoError> {
    Ok(AccountEvent {
        seq: integer_field(map, "seq")?,
        did: string_field(map, "did")?,
        time: string_field(map, "time")?,
        active: boolean_field(map, "active")?,
        status: optional_string_field(map, "status"),
    })
}

fn decode_info(map: &BTreeMap<String, LexValue>) -> Result<InfoEvent, RepoError> {
    Ok(InfoEvent {
        name: string_field(map, "name")?,
        message: optional_string_field(map, "message"),
    })
}

fn decode_ops(value: Option<&LexValue>) -> Result<Vec<RepoOp>, RepoError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Some(array) = value.as_array() else {
        return Err(RepoError::InvalidCommit("ops must be an array".into()));
    };
    array.iter().map(decode_op).collect()
}

fn decode_op(value: &LexValue) -> Result<RepoOp, RepoError> {
    let map = value
        .as_map()
        .ok_or_else(|| RepoError::InvalidCommit("repoOp must be a map".into()))?;
    let action_str = string_field(map, "action")?;
    let action = match action_str.as_str() {
        "create" => RepoOpAction::Create,
        "update" => RepoOpAction::Update,
        "delete" => RepoOpAction::Delete,
        other => {
            return Err(RepoError::InvalidCommit(format!(
                "unknown repoOp action: {other}"
            )));
        }
    };
    let path = string_field(map, "path")?;

    // `cid` is nullable on delete, required on create/update.
    let cid = match map.get("cid") {
        Some(LexValue::Cid(c)) => Some(c.clone()),
        Some(LexValue::Null) | None => None,
        _ => {
            return Err(RepoError::InvalidCommit(
                "repoOp.cid must be CID or null".into(),
            ));
        }
    };
    if cid.is_none() && matches!(action, RepoOpAction::Create | RepoOpAction::Update) {
        return Err(RepoError::InvalidCommit(format!(
            "repoOp action `{action_str}` requires a non-null cid"
        )));
    }

    let prev = optional_cid_field(map, "prev");

    Ok(RepoOp {
        action,
        path,
        cid,
        prev,
    })
}

fn decode_cid_array(value: Option<&LexValue>) -> Result<Vec<Cid>, RepoError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Some(array) = value.as_array() else {
        return Err(RepoError::InvalidCommit("expected array of CIDs".into()));
    };
    let mut out = Vec::with_capacity(array.len());
    for item in array {
        match item {
            LexValue::Cid(c) => out.push(c.clone()),
            _ => {
                return Err(RepoError::InvalidCommit(
                    "non-CID entry in CID array".into(),
                ));
            }
        }
    }
    Ok(out)
}

// ── field accessor helpers ──────────────────────────────────────────

fn string_field(map: &BTreeMap<String, LexValue>, key: &str) -> Result<String, RepoError> {
    match map.get(key) {
        Some(LexValue::String(s)) => Ok(s.clone()),
        _ => Err(RepoError::InvalidCommit(format!(
            "firehose event missing string field `{key}`"
        ))),
    }
}

fn integer_field(map: &BTreeMap<String, LexValue>, key: &str) -> Result<i64, RepoError> {
    match map.get(key) {
        Some(LexValue::Integer(n)) => Ok(*n),
        _ => Err(RepoError::InvalidCommit(format!(
            "firehose event missing integer field `{key}`"
        ))),
    }
}

fn boolean_field(map: &BTreeMap<String, LexValue>, key: &str) -> Result<bool, RepoError> {
    match map.get(key) {
        Some(LexValue::Bool(b)) => Ok(*b),
        _ => Err(RepoError::InvalidCommit(format!(
            "firehose event missing boolean field `{key}`"
        ))),
    }
}

fn bytes_field(map: &BTreeMap<String, LexValue>, key: &str) -> Result<Vec<u8>, RepoError> {
    match map.get(key) {
        Some(LexValue::Bytes(b)) => Ok(b.clone()),
        _ => Err(RepoError::InvalidCommit(format!(
            "firehose event missing bytes field `{key}`"
        ))),
    }
}

fn cid_field(map: &BTreeMap<String, LexValue>, key: &str) -> Result<Cid, RepoError> {
    match map.get(key) {
        Some(LexValue::Cid(c)) => Ok(c.clone()),
        _ => Err(RepoError::InvalidCommit(format!(
            "firehose event missing CID field `{key}`"
        ))),
    }
}

fn nullable_string_field(
    map: &BTreeMap<String, LexValue>,
    key: &str,
) -> Result<Option<String>, RepoError> {
    match map.get(key) {
        Some(LexValue::String(s)) => Ok(Some(s.clone())),
        // The commit schema marks `since` as nullable but REQUIRED —
        // i.e. the key must be present. We accept absence too, for
        // robustness against non-spec-conformant upstreams.
        Some(LexValue::Null) | None => Ok(None),
        _ => Err(RepoError::InvalidCommit(format!(
            "field `{key}` must be string or null"
        ))),
    }
}

fn optional_string_field(map: &BTreeMap<String, LexValue>, key: &str) -> Option<String> {
    match map.get(key) {
        Some(LexValue::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn optional_cid_field(map: &BTreeMap<String, LexValue>, key: &str) -> Option<Cid> {
    match map.get(key) {
        Some(LexValue::Cid(c)) => Some(c.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_blue_lex_cbor::cid_for_lex;

    fn dummy_cid(seed: &[u8]) -> Cid {
        cid_for_lex(&LexValue::Bytes(seed.to_vec())).unwrap()
    }

    fn base_commit_map() -> BTreeMap<String, LexValue> {
        let mut m = BTreeMap::new();
        m.insert("seq".into(), LexValue::Integer(42));
        m.insert("rebase".into(), LexValue::Bool(false));
        m.insert("tooBig".into(), LexValue::Bool(false));
        m.insert("repo".into(), LexValue::String("did:plc:repo".into()));
        m.insert("commit".into(), LexValue::Cid(dummy_cid(b"commit")));
        m.insert("rev".into(), LexValue::String("3jzfcijpj2z2a".into()));
        m.insert("since".into(), LexValue::Null);
        m.insert("blocks".into(), LexValue::Bytes(vec![1, 2, 3]));
        m.insert("ops".into(), LexValue::Array(Vec::new()));
        m.insert("blobs".into(), LexValue::Array(Vec::new()));
        m.insert(
            "time".into(),
            LexValue::String("2025-01-01T00:00:00Z".into()),
        );
        m
    }

    // ── commit ──

    #[test]
    fn decodes_commit_with_no_ops() {
        let body = LexValue::Map(base_commit_map());
        let evt = decode_event(Some("#commit"), &body).unwrap();
        let FirehoseEvent::Commit(c) = evt else {
            panic!("expected Commit");
        };
        assert_eq!(c.seq, 42);
        assert_eq!(c.repo, "did:plc:repo");
        assert_eq!(c.ops.len(), 0);
        assert!(c.since.is_none());
    }

    #[test]
    fn decodes_commit_with_create_op() {
        let mut m = base_commit_map();
        let mut op = BTreeMap::new();
        op.insert("action".into(), LexValue::String("create".into()));
        op.insert(
            "path".into(),
            LexValue::String("app.bsky.feed.post/abc".into()),
        );
        op.insert("cid".into(), LexValue::Cid(dummy_cid(b"rec")));
        m.insert("ops".into(), LexValue::Array(vec![LexValue::Map(op)]));

        let body = LexValue::Map(m);
        let evt = decode_event(Some("#commit"), &body).unwrap();
        let FirehoseEvent::Commit(c) = evt else {
            panic!("expected Commit");
        };
        assert_eq!(c.ops.len(), 1);
        assert_eq!(c.ops[0].action, RepoOpAction::Create);
        assert_eq!(c.ops[0].path, "app.bsky.feed.post/abc");
        assert!(c.ops[0].cid.is_some());
    }

    #[test]
    fn decodes_commit_with_delete_op_null_cid() {
        let mut m = base_commit_map();
        let mut op = BTreeMap::new();
        op.insert("action".into(), LexValue::String("delete".into()));
        op.insert("path".into(), LexValue::String("coll/k".into()));
        op.insert("cid".into(), LexValue::Null);
        m.insert("ops".into(), LexValue::Array(vec![LexValue::Map(op)]));
        let body = LexValue::Map(m);
        let evt = decode_event(Some("#commit"), &body).unwrap();
        let FirehoseEvent::Commit(c) = evt else {
            panic!("expected Commit");
        };
        assert_eq!(c.ops[0].action, RepoOpAction::Delete);
        assert!(c.ops[0].cid.is_none());
    }

    #[test]
    fn create_op_requires_non_null_cid() {
        let mut m = base_commit_map();
        let mut op = BTreeMap::new();
        op.insert("action".into(), LexValue::String("create".into()));
        op.insert("path".into(), LexValue::String("coll/k".into()));
        op.insert("cid".into(), LexValue::Null);
        m.insert("ops".into(), LexValue::Array(vec![LexValue::Map(op)]));
        let body = LexValue::Map(m);
        let err = decode_event(Some("#commit"), &body).unwrap_err();
        assert!(matches!(err, RepoError::InvalidCommit(_)));
    }

    #[test]
    fn unknown_op_action_is_error() {
        let mut m = base_commit_map();
        let mut op = BTreeMap::new();
        op.insert("action".into(), LexValue::String("yeet".into()));
        op.insert("path".into(), LexValue::String("coll/k".into()));
        op.insert("cid".into(), LexValue::Cid(dummy_cid(b"x")));
        m.insert("ops".into(), LexValue::Array(vec![LexValue::Map(op)]));
        let body = LexValue::Map(m);
        let err = decode_event(Some("#commit"), &body).unwrap_err();
        assert!(matches!(err, RepoError::InvalidCommit(_)));
    }

    #[test]
    fn commit_missing_required_field_is_error() {
        let mut m = base_commit_map();
        m.remove("seq");
        let body = LexValue::Map(m);
        let err = decode_event(Some("#commit"), &body).unwrap_err();
        assert!(matches!(err, RepoError::InvalidCommit(_)));
    }

    // ── sync / identity / account / info ──

    #[test]
    fn decodes_sync() {
        let mut m = BTreeMap::new();
        m.insert("seq".into(), LexValue::Integer(7));
        m.insert("did".into(), LexValue::String("did:plc:x".into()));
        m.insert("blocks".into(), LexValue::Bytes(vec![0xca, 0xfe]));
        m.insert("rev".into(), LexValue::String("3jzfcijpj2z2a".into()));
        m.insert(
            "time".into(),
            LexValue::String("2025-01-01T00:00:00Z".into()),
        );
        let evt = decode_event(Some("#sync"), &LexValue::Map(m)).unwrap();
        let FirehoseEvent::Sync(s) = evt else {
            panic!("expected Sync");
        };
        assert_eq!(s.seq, 7);
        assert_eq!(s.blocks, vec![0xca, 0xfe]);
    }

    #[test]
    fn decodes_identity_with_handle() {
        let mut m = BTreeMap::new();
        m.insert("seq".into(), LexValue::Integer(1));
        m.insert("did".into(), LexValue::String("did:plc:x".into()));
        m.insert("time".into(), LexValue::String("t".into()));
        m.insert("handle".into(), LexValue::String("alice.test".into()));
        let evt = decode_event(Some("#identity"), &LexValue::Map(m)).unwrap();
        let FirehoseEvent::Identity(i) = evt else {
            panic!("expected Identity");
        };
        assert_eq!(i.handle.as_deref(), Some("alice.test"));
    }

    #[test]
    fn decodes_identity_without_handle() {
        let mut m = BTreeMap::new();
        m.insert("seq".into(), LexValue::Integer(1));
        m.insert("did".into(), LexValue::String("did:plc:x".into()));
        m.insert("time".into(), LexValue::String("t".into()));
        let evt = decode_event(Some("#identity"), &LexValue::Map(m)).unwrap();
        let FirehoseEvent::Identity(i) = evt else {
            panic!("expected Identity");
        };
        assert!(i.handle.is_none());
    }

    #[test]
    fn decodes_account_with_status() {
        let mut m = BTreeMap::new();
        m.insert("seq".into(), LexValue::Integer(1));
        m.insert("did".into(), LexValue::String("did:plc:x".into()));
        m.insert("time".into(), LexValue::String("t".into()));
        m.insert("active".into(), LexValue::Bool(false));
        m.insert("status".into(), LexValue::String("takendown".into()));
        let evt = decode_event(Some("#account"), &LexValue::Map(m)).unwrap();
        let FirehoseEvent::Account(a) = evt else {
            panic!("expected Account");
        };
        assert!(!a.active);
        assert_eq!(a.status.as_deref(), Some("takendown"));
    }

    #[test]
    fn decodes_info() {
        let mut m = BTreeMap::new();
        m.insert("name".into(), LexValue::String("OutdatedCursor".into()));
        m.insert("message".into(), LexValue::String("too old".into()));
        let evt = decode_event(Some("#info"), &LexValue::Map(m)).unwrap();
        let FirehoseEvent::Info(i) = evt else {
            panic!("expected Info");
        };
        assert_eq!(i.name, "OutdatedCursor");
        assert_eq!(i.message.as_deref(), Some("too old"));
    }

    // ── unknown discriminator ──

    #[test]
    fn unknown_discriminator_returns_unknown_variant() {
        let mut m = BTreeMap::new();
        m.insert("foo".into(), LexValue::Integer(1));
        let evt = decode_event(Some("#futurism"), &LexValue::Map(m)).unwrap();
        match evt {
            FirehoseEvent::Unknown { r#type, .. } => assert_eq!(r#type, "#futurism"),
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn missing_discriminator_returns_unknown_variant() {
        let body = LexValue::Map(BTreeMap::new());
        let evt = decode_event(None, &body).unwrap();
        assert!(matches!(evt, FirehoseEvent::Unknown { .. }));
    }

    #[test]
    fn non_map_body_is_error() {
        let body = LexValue::Integer(42);
        let err = decode_event(Some("#commit"), &body).unwrap_err();
        assert!(matches!(err, RepoError::InvalidCommit(_)));
    }

    // ── FirehoseEvent accessors ──

    #[test]
    fn seq_and_did_accessors() {
        let evt = decode_event(Some("#commit"), &LexValue::Map(base_commit_map())).unwrap();
        assert_eq!(evt.seq(), Some(42));
        assert_eq!(evt.did(), Some("did:plc:repo"));

        let mut info = BTreeMap::new();
        info.insert("name".into(), LexValue::String("x".into()));
        let info_evt = decode_event(Some("#info"), &LexValue::Map(info)).unwrap();
        assert_eq!(info_evt.seq(), None);
        assert_eq!(info_evt.did(), None);
    }
}
