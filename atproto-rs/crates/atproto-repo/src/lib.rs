//! AT Protocol repository: MST, CAR files, commits, block storage.
//!
//! Implements the Merkle Search Tree (MST) used for AT Protocol repositories,
//! CAR file encoding/decoding, and block storage abstractions.
//!
//! # Examples
//!
//! ```
//! use atproto_repo::{MstNode, BlockMap, CidSet, blocks_to_car, read_car};
//! use atproto_lex_data::LexValue;
//! use atproto_lex_cbor::cid_for_lex;
//! use std::collections::BTreeMap;
//!
//! // Create a value and compute its CID
//! let mut map = BTreeMap::new();
//! map.insert("text".into(), LexValue::String("Hello!".into()));
//! let cid = cid_for_lex(&LexValue::Map(map)).unwrap();
//!
//! // Build an MST (immutable, copy-on-write)
//! let mst = MstNode::empty();
//! let mst = mst.add("app.bsky.feed.post/abc123", cid.clone()).unwrap();
//! assert_eq!(mst.leaves().len(), 1);
//!
//! // BlockMap for storing CID -> bytes
//! let mut blocks = BlockMap::new();
//! blocks.set(cid.clone(), vec![1, 2, 3]);
//! assert_eq!(blocks.len(), 1);
//!
//! // CidSet for tracking seen CIDs
//! let mut seen = CidSet::new();
//! seen.add(cid.clone());
//! assert!(seen.has(&cid));
//! ```

pub mod block_map;
pub mod car;
pub mod cid_set;
pub mod error;
pub mod mst;

pub use block_map::BlockMap;
pub use car::{CarBlock, blocks_to_car, read_car, read_car_with_root};
pub use cid_set::CidSet;
pub use error::RepoError;
pub use mst::{Leaf, MstNode, NodeEntry};
