//! Combined identity resolver for both DIDs and handles.

use crate::cache::DidCache;
use crate::did::DidResolver;
use crate::handle::HandleResolver;
use crate::types::IdentityResolverOpts;

/// Combined resolver for DID and handle resolution.
pub struct IdResolver {
    /// Handle resolver.
    pub handle: HandleResolver,
    /// DID resolver.
    pub did: DidResolver,
}

impl IdResolver {
    /// Create a new IdResolver with the given options.
    pub fn new(opts: IdentityResolverOpts, cache: Option<Box<dyn DidCache>>) -> Self {
        IdResolver {
            handle: HandleResolver::new(opts.timeout_ms),
            did: DidResolver::new(opts.plc_url.as_deref(), opts.timeout_ms, cache),
        }
    }
}

impl Default for IdResolver {
    fn default() -> Self {
        Self::new(IdentityResolverOpts::default(), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_default_resolver() {
        let _resolver = IdResolver::default();
    }

    #[test]
    fn create_with_options() {
        let opts = IdentityResolverOpts {
            timeout_ms: 5000,
            plc_url: Some("https://plc.example.com".to_string()),
            backup_nameservers: None,
        };
        let _resolver = IdResolver::new(opts, None);
    }
}
