//! Combined identity resolver for both DIDs and handles.

use std::sync::Arc;

use proto_blue_common::DidDocument;
use proto_blue_common::fetch::FetchHandler;

use crate::cache::DidCache;
use crate::did::DidResolver;
use crate::error::IdentityError;
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
    /// Create a new IdResolver with the given options, using the crate's
    /// default native fetch handler (`reqwest`).
    ///
    /// Requires `fetch-reqwest` + `dns` (both default on native). For
    /// wasm, use [`Self::with_fetch_handler`].
    #[cfg(all(feature = "fetch-reqwest", feature = "dns"))]
    pub fn new(opts: IdentityResolverOpts, cache: Option<Arc<dyn DidCache>>) -> Self {
        // Parse backup nameserver strings into IP addresses; silently
        // drop entries that don't parse (they were a caller typo, not a
        // reason to fail every request).
        let backups: Vec<std::net::IpAddr> = opts
            .backup_nameservers
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        IdResolver {
            handle: HandleResolver::with_backup_nameservers(opts.timeout_ms, backups),
            did: DidResolver::new(opts.plc_url.as_deref(), opts.timeout_ms, cache),
        }
    }

    /// Create a new IdResolver with a user-supplied [`FetchHandler`].
    ///
    /// This is the constructor for wasm builds (no DNS), for tests that
    /// want to mock HTTP, and for callers that want to share a single
    /// transport across multiple resolvers.
    pub fn with_fetch_handler(
        opts: IdentityResolverOpts,
        cache: Option<Arc<dyn DidCache>>,
        fetcher: Arc<dyn FetchHandler>,
    ) -> Self {
        IdResolver {
            handle: HandleResolver::with_fetch_handler(opts.timeout_ms, fetcher.clone()),
            did: DidResolver::with_fetch_handler(
                opts.plc_url.as_deref(),
                opts.timeout_ms,
                cache,
                fetcher,
            ),
        }
    }

    /// Resolve a handle to its DID and DID document, **with loop-back
    /// verification** against `alsoKnownAs`.
    ///
    /// This is the safe path that callers should prefer when the binding
    /// matters (login flows, authored-by checks, etc.). The algorithm:
    ///
    /// 1. Resolve handle → DID (via DNS TXT or well-known HTTPS).
    /// 2. Resolve DID → DID document (via did:plc / did:web / did:key).
    /// 3. Assert the document's `alsoKnownAs` contains `at://<handle>`.
    ///
    /// Without step 3, a malicious DNS or HTTP response could point a
    /// handle at an unrelated DID whose owner never claimed that handle
    /// — a classic handle-takeover attack. The atproto spec requires the
    /// DID to reference the handle back; this method enforces it.
    ///
    /// Returns `(did, document)` on success. If the handle doesn't
    /// resolve, returns `Err(HandleNotFound)`. If the DID doesn't
    /// resolve, returns `Err(DidNotFound)`. If the binding is not
    /// mutually asserted, returns `Err(HandleDidMismatch)`.
    pub async fn resolve_handle_verified(
        &self,
        handle: &str,
    ) -> Result<(String, DidDocument), IdentityError> {
        let did = self
            .handle
            .resolve(handle)
            .await?
            .ok_or_else(|| IdentityError::HandleNotFound(handle.to_string()))?;

        let doc = self
            .did
            .ensure_resolve(&did, /*force_refresh=*/ false)
            .await?;

        if !did_doc_claims_handle(&doc, handle) {
            return Err(IdentityError::HandleDidMismatch {
                handle: handle.to_string(),
                did: did.clone(),
            });
        }

        Ok((did, doc))
    }
}

#[cfg(all(feature = "fetch-reqwest", feature = "dns"))]
impl Default for IdResolver {
    fn default() -> Self {
        Self::new(IdentityResolverOpts::default(), None)
    }
}

/// Check whether `doc.alsoKnownAs` contains `at://<handle>`, case-
/// insensitively on the handle (handles are ASCII-lowercase-canonical
/// per atproto syntax rules, but we match lenient to avoid rejecting
/// valid documents authored with upper-case scratch).
pub(crate) fn did_doc_claims_handle(doc: &DidDocument, handle: &str) -> bool {
    let needle = format!("at://{}", handle.to_ascii_lowercase());
    doc.also_known_as
        .iter()
        .any(|aka| aka.to_ascii_lowercase() == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_blue_common::parse_did_document;

    #[cfg(all(feature = "fetch-reqwest", feature = "dns"))]
    #[test]
    fn create_default_resolver() {
        let _resolver = IdResolver::default();
    }

    #[cfg(all(feature = "fetch-reqwest", feature = "dns"))]
    #[test]
    fn create_with_options() {
        let opts = IdentityResolverOpts {
            timeout_ms: 5000,
            plc_url: Some("https://plc.example.com".to_string()),
            backup_nameservers: None,
        };
        let _resolver = IdResolver::new(opts, None);
    }

    #[cfg(all(feature = "fetch-reqwest", feature = "dns"))]
    #[test]
    fn backup_nameservers_are_threaded_through_opts() {
        let opts = IdentityResolverOpts {
            timeout_ms: 5000,
            plc_url: None,
            backup_nameservers: Some(vec![
                "8.8.8.8".to_string(),
                "1.1.1.1".to_string(),
                "not-an-ip".to_string(), // silently dropped
            ]),
        };
        let resolver = IdResolver::new(opts, None);
        // Two valid IPs survive parsing; the garbage string is dropped.
        assert_eq!(resolver.handle.backup_nameservers.len(), 2);
    }

    // ── did_doc_claims_handle ───────────────────────────────────────

    fn doc_with_aka(aka: &[&str]) -> DidDocument {
        let also = aka
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            r##"{{"id":"did:plc:test","alsoKnownAs":[{also}],"verificationMethod":[],"service":[]}}"##
        );
        parse_did_document(&json).unwrap()
    }

    #[test]
    fn claims_handle_matches_exact() {
        let doc = doc_with_aka(&["at://alice.bsky.social"]);
        assert!(did_doc_claims_handle(&doc, "alice.bsky.social"));
    }

    #[test]
    fn claims_handle_is_case_insensitive() {
        let doc = doc_with_aka(&["at://Alice.Bsky.Social"]);
        assert!(did_doc_claims_handle(&doc, "alice.bsky.social"));
    }

    #[test]
    fn claims_handle_rejects_missing() {
        let doc = doc_with_aka(&["at://bob.bsky.social"]);
        assert!(!did_doc_claims_handle(&doc, "alice.bsky.social"));
    }

    #[test]
    fn claims_handle_rejects_empty_aka() {
        let doc = doc_with_aka(&[]);
        assert!(!did_doc_claims_handle(&doc, "alice.bsky.social"));
    }

    #[test]
    fn claims_handle_ignores_non_matching_entries() {
        let doc = doc_with_aka(&[
            "https://alice.example.com",
            "at://someone-else.test",
            "mailto:alice@example.com",
        ]);
        assert!(!did_doc_claims_handle(&doc, "alice.bsky.social"));
    }
}
