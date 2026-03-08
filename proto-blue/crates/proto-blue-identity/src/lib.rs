//! AT Protocol identity resolution: DID and handle resolution.
//!
//! Provides DID resolution (did:plc via PLC directory, did:web via HTTPS)
//! and handle resolution (DNS TXT records, HTTPS fallback).

pub mod cache;
pub mod did;
pub mod error;
pub mod handle;
pub mod id_resolver;
pub mod types;

pub use cache::{DidCache, MemoryCache};
pub use did::{DidResolver, ensure_atp_document};
pub use error::IdentityError;
pub use handle::HandleResolver;
pub use id_resolver::IdResolver;
pub use types::{AtprotoData, CacheResult, IdentityResolverOpts};
