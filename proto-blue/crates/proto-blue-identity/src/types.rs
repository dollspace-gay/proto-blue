//! Identity resolution types.

pub use proto_blue_common::DidDocument;

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

/// Options for creating an `IdResolver`.
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
        Self {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_resolver_opts_default_timeout_ms() {
        let opts = IdentityResolverOpts::default();
        assert_eq!(opts.timeout_ms, 3000);
    }

    #[test]
    fn identity_resolver_opts_default_plc_url_is_none() {
        let opts = IdentityResolverOpts::default();
        assert!(opts.plc_url.is_none());
    }

    #[test]
    fn identity_resolver_opts_default_backup_nameservers_is_none() {
        let opts = IdentityResolverOpts::default();
        assert!(opts.backup_nameservers.is_none());
    }

    #[test]
    fn atproto_data_construction_and_field_access() {
        let data = AtprotoData {
            did: "did:plc:abc123".into(),
            signing_key: "did:key:zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF".into(),
            handle: "alice.bsky.social".into(),
            pds: "https://bsky.social".into(),
        };
        assert_eq!(data.did, "did:plc:abc123");
        assert_eq!(
            data.signing_key,
            "did:key:zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF"
        );
        assert_eq!(data.handle, "alice.bsky.social");
        assert_eq!(data.pds, "https://bsky.social");
    }

    #[test]
    fn atproto_data_clone() {
        let data = AtprotoData {
            did: "did:plc:test".into(),
            signing_key: "did:key:zTest".into(),
            handle: "test.bsky.social".into(),
            pds: "https://pds.example.com".into(),
        };
        let cloned = data.clone();
        assert_eq!(data.did, cloned.did);
        assert_eq!(data.signing_key, cloned.signing_key);
        assert_eq!(data.handle, cloned.handle);
        assert_eq!(data.pds, cloned.pds);
    }

    #[test]
    fn cache_result_construction_not_stale_not_expired() {
        let doc = DidDocument {
            id: "did:plc:cached".into(),
            also_known_as: vec![],
            verification_method: vec![],
            service: vec![],
        };
        let result = CacheResult {
            did: "did:plc:cached".into(),
            doc,
            updated_at: 1700000000,
            stale: false,
            expired: false,
        };
        assert_eq!(result.did, "did:plc:cached");
        assert_eq!(result.updated_at, 1700000000);
        assert!(!result.stale);
        assert!(!result.expired);
    }

    #[test]
    fn cache_result_stale_flag() {
        let doc = DidDocument {
            id: "did:plc:stale".into(),
            also_known_as: vec![],
            verification_method: vec![],
            service: vec![],
        };
        let result = CacheResult {
            did: "did:plc:stale".into(),
            doc,
            updated_at: 1600000000,
            stale: true,
            expired: false,
        };
        assert!(result.stale);
        assert!(!result.expired);
    }

    #[test]
    fn cache_result_expired_flag() {
        let doc = DidDocument {
            id: "did:plc:expired".into(),
            also_known_as: vec![],
            verification_method: vec![],
            service: vec![],
        };
        let result = CacheResult {
            did: "did:plc:expired".into(),
            doc,
            updated_at: 1500000000,
            stale: true,
            expired: true,
        };
        assert!(result.stale);
        assert!(result.expired);
    }

    #[test]
    fn cache_result_doc_preserves_id() {
        let doc = DidDocument {
            id: "did:plc:doccheck".into(),
            also_known_as: vec!["at://test.bsky.social".into()],
            verification_method: vec![],
            service: vec![],
        };
        let result = CacheResult {
            did: "did:plc:doccheck".into(),
            doc,
            updated_at: 0,
            stale: false,
            expired: false,
        };
        assert_eq!(result.doc.id, "did:plc:doccheck");
        assert_eq!(result.doc.also_known_as, vec!["at://test.bsky.social"]);
    }
}
