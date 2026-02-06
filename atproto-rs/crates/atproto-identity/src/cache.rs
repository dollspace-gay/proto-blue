//! DID document caching.

use std::collections::HashMap;

use atproto_common::{DAY, DidDocument, HOUR};

use crate::types::CacheResult;

/// Trait for DID document caching.
pub trait DidCache: Send + Sync {
    /// Cache a DID document.
    fn cache_did(
        &self,
        did: &str,
        doc: DidDocument,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;

    /// Check the cache for a DID.
    fn check_cache(
        &self,
        did: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<CacheResult>> + Send + '_>>;

    /// Clear a single cache entry.
    fn clear_entry(
        &self,
        did: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;

    /// Clear the entire cache.
    fn clear(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
}

/// An entry in the memory cache.
struct CacheVal {
    doc: DidDocument,
    updated_at: u64,
}

/// In-memory DID document cache with stale and max TTL.
pub struct MemoryCache {
    stale_ttl_ms: u64,
    max_ttl_ms: u64,
    cache: std::sync::Mutex<HashMap<String, CacheVal>>,
}

impl MemoryCache {
    /// Create a new memory cache with optional TTL overrides.
    pub fn new(stale_ttl_ms: Option<u64>, max_ttl_ms: Option<u64>) -> Self {
        MemoryCache {
            stale_ttl_ms: stale_ttl_ms.unwrap_or(HOUR),
            max_ttl_ms: max_ttl_ms.unwrap_or(DAY),
            cache: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

impl DidCache for MemoryCache {
    fn cache_did(
        &self,
        did: &str,
        doc: DidDocument,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        let did = did.to_string();
        Box::pin(async move {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(
                did,
                CacheVal {
                    doc,
                    updated_at: Self::now_ms(),
                },
            );
        })
    }

    fn check_cache(
        &self,
        did: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<CacheResult>> + Send + '_>> {
        let did = did.to_string();
        Box::pin(async move {
            let cache = self.cache.lock().unwrap();
            let val = cache.get(&did)?;
            let now = Self::now_ms();
            let expired = now > val.updated_at + self.max_ttl_ms;
            let stale = now > val.updated_at + self.stale_ttl_ms;
            Some(CacheResult {
                did,
                doc: val.doc.clone(),
                updated_at: val.updated_at,
                stale,
                expired,
            })
        })
    }

    fn clear_entry(
        &self,
        did: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        let did = did.to_string();
        Box::pin(async move {
            let mut cache = self.cache.lock().unwrap();
            cache.remove(&did);
        })
    }

    fn clear(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let mut cache = self.cache.lock().unwrap();
            cache.clear();
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_common::parse_did_document;

    fn sample_doc() -> DidDocument {
        let json = r#"{"id": "did:plc:test", "verificationMethod": [], "service": []}"#;
        parse_did_document(json).unwrap()
    }

    #[tokio::test]
    async fn cache_and_retrieve() {
        let cache = MemoryCache::new(None, None);
        let doc = sample_doc();
        cache.cache_did("did:plc:test", doc.clone()).await;

        let result = cache.check_cache("did:plc:test").await;
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.did, "did:plc:test");
        assert_eq!(result.doc.id, "did:plc:test");
        assert!(!result.stale);
        assert!(!result.expired);
    }

    #[tokio::test]
    async fn cache_miss() {
        let cache = MemoryCache::new(None, None);
        let result = cache.check_cache("did:plc:nonexistent").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn cache_clear_entry() {
        let cache = MemoryCache::new(None, None);
        cache.cache_did("did:plc:test", sample_doc()).await;
        cache.clear_entry("did:plc:test").await;
        let result = cache.check_cache("did:plc:test").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn cache_clear_all() {
        let cache = MemoryCache::new(None, None);
        cache.cache_did("did:plc:a", sample_doc()).await;
        cache.cache_did("did:plc:b", sample_doc()).await;
        cache.clear().await;
        assert!(cache.check_cache("did:plc:a").await.is_none());
        assert!(cache.check_cache("did:plc:b").await.is_none());
    }

    #[tokio::test]
    async fn cache_stale_ttl() {
        // Use 0ms stale TTL to force stale immediately
        let cache = MemoryCache::new(Some(0), None);
        cache.cache_did("did:plc:test", sample_doc()).await;
        // Small delay to ensure time passes
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        let result = cache.check_cache("did:plc:test").await.unwrap();
        assert!(result.stale);
        assert!(!result.expired);
    }

    #[tokio::test]
    async fn cache_expired_ttl() {
        // Use 0ms max TTL to force expiry immediately
        let cache = MemoryCache::new(Some(0), Some(0));
        cache.cache_did("did:plc:test", sample_doc()).await;
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        let result = cache.check_cache("did:plc:test").await.unwrap();
        assert!(result.expired);
    }
}
