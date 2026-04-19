//! # proto-blue
//!
//! Full-stack AT Protocol SDK for Rust.
//!
//! This crate re-exports the individual proto-blue modules so downstream code
//! can depend on a single crate:
//!
//! ```toml
//! [dependencies]
//! proto-blue = "0.2"
//! ```
//!
//! ```rust,no_run
//! use proto_blue::api::Agent;
//! use proto_blue::syntax::Did;
//! ```
//!
//! ## Feature flags
//!
//! The default feature set is **`full`** — everything on, matching the
//! pre-0.2.2 API surface. For constrained targets (most importantly
//! `wasm32-unknown-unknown`) turn defaults off and opt into only what you
//! need:
//!
//! ```toml
//! [dependencies]
//! proto-blue = { version = "0.2", default-features = false }
//! ```
//!
//! Available features:
//!
//! | Feature    | Re-exports                             | WASM? |
//! |------------|----------------------------------------|-------|
//! | (none)     | `syntax`, `crypto`, `lex_data`, `lex_cbor`, `lex_json`, `common`, `lexicon`, `repo` | ✅ |
//! | `net`      | `xrpc`                                 | 🚧 (issue #25) |
//! | `ws`       | `ws`, enables `repo::Firehose`         | 🚧 (issue #27) |
//! | `resolver` | `identity`                             | 🚧 (issue #26) |
//! | `oauth`    | `oauth`                                | 🚧 |
//! | `api`      | `api`                                  | 🚧 |
//! | `full`     | everything                             | ❌ (default — native only) |

/// AT Protocol identifier types: DID, Handle, NSID, AT-URI, TID, RecordKey, Datetime.
pub use proto_blue_syntax as syntax;

/// Cryptographic primitives: P-256/K-256 key pairs, signing, did:key, SHA-256.
pub use proto_blue_crypto as crypto;

/// Core Lexicon data model: `LexValue`, `BlobRef`, `Cid`.
pub use proto_blue_lex_data as lex_data;

/// DAG-CBOR encoding and decoding with deterministic map ordering.
pub use proto_blue_lex_cbor as lex_cbor;

/// JSON ↔ Lexicon value conversion with `$link`/`$bytes` encoding.
pub use proto_blue_lex_json as lex_json;

/// Shared utilities: DID document parsing, TID generation, retry helpers.
pub use proto_blue_common as common;

/// Lexicon schema types, registry, and validation engine.
pub use proto_blue_lexicon as lexicon;

/// Repository primitives: Merkle Search Tree, CAR files, block storage.
///
/// When the top-level `ws` feature is enabled, `repo::Firehose` (a
/// live-connection firehose client) is also available.
pub use proto_blue_repo as repo;

/// XRPC HTTP client for AT Protocol queries and procedures.
#[cfg(feature = "net")]
pub use proto_blue_xrpc as xrpc;

/// Auto-reconnecting WebSocket client for event streams.
#[cfg(feature = "ws")]
pub use proto_blue_ws as ws;

/// DID and handle resolution with caching.
#[cfg(feature = "resolver")]
pub use proto_blue_identity as identity;

/// High-level API: Agent, rich text, moderation, session management.
#[cfg(feature = "api")]
pub use proto_blue_api as api;

/// OAuth 2.0 client: DPoP, PKCE, PAR, token management.
#[cfg(feature = "oauth")]
pub use proto_blue_oauth as oauth;
