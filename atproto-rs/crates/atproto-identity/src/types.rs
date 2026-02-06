//! Identity resolution types.

pub use atproto_common::DidDocument;

/// AT Protocol data extracted from a DID document.
#[derive(Debug, Clone)]
pub struct AtprotoData {
    /// The DID.
    pub did: String,
    /// The `did:key:...` signing key.
    pub signing_key: String,
    /// The handle (from `alsoKnownAs`).
    pub handle: String,
    /// The PDS endpoint URL.
    pub pds: String,
}

/// Options for creating an IdResolver.
#[derive(Debug, Clone)]
pub struct IdentityResolverOpts {
    /// Timeout for requests in milliseconds.
    pub timeout_ms: u64,
    /// PLC directory URL (default: `https://plc.directory`).
    pub plc_url: Option<String>,
    /// Backup DNS nameservers for handle resolution.
    pub backup_nameservers: Option<Vec<String>>,
}

impl Default for IdentityResolverOpts {
    fn default() -> Self {
        IdentityResolverOpts {
            timeout_ms: 3000,
            plc_url: None,
            backup_nameservers: None,
        }
    }
}

/// Cached DID resolution result.
#[derive(Debug, Clone)]
pub struct CacheResult {
    pub did: String,
    pub doc: DidDocument,
    pub updated_at: u64,
    pub stale: bool,
    pub expired: bool,
}
