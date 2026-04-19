//! Pluggable key-value storage for OAuth flow state.
//!
//! Clients need to persist three kinds of state across an OAuth flow:
//!
//! 1. **Authorization state** — the CSRF `state` parameter, PKCE
//!    verifier, and ephemeral DPoP key, keyed by `state`. Written
//!    during [`OAuthClient::authorize`](crate::OAuthClient::authorize)
//!    and read during
//!    [`OAuthClient::callback`](crate::OAuthClient::callback).
//! 2. **Session state** — a durable [`TokenSet`](crate::TokenSet) plus
//!    its DPoP key, keyed by the user's DID. Used to reattach to an
//!    authenticated user across process restarts.
//! 3. **DPoP nonces** — per-origin nonces rotated by the AS and RS.
//!    Already handled by [`DpopNonceCache`](crate::DpopNonceCache)
//!    in-process; callers who want durable nonce caching can implement
//!    this trait and plug it in.
//!
//! Each of these is a mapping from `String` to a JSON-serializable
//! value. [`SimpleStore`] is the minimum interface needed; the
//! in-memory [`MemoryStore`] is sufficient for CLIs, tests, and
//! single-process servers. Multi-process deployments should implement
//! the trait against Redis, Postgres, sqlite, etc.
//!
//! The trait is deliberately thin: `get`/`set`/`del`. Anything richer
//! (atomic swap, TTL on write, bulk ops) belongs in concrete impls.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::OAuthError;

/// Async key-value store over JSON-serializable values.
///
/// Implementors back OAuth state by whatever durable / shared storage
/// suits the deployment. The trait is object-safe so `OAuthClient` can
/// hold `Arc<dyn SimpleStore>`.
#[async_trait::async_trait]
pub trait SimpleStore: Send + Sync + 'static {
    /// Fetch a value by key. Returns `Ok(None)` on miss.
    async fn get(&self, key: &str) -> Result<Option<serde_json::Value>, OAuthError>;

    /// Upsert a value. Overwrites any existing entry.
    async fn set(&self, key: &str, value: serde_json::Value) -> Result<(), OAuthError>;

    /// Remove an entry. A no-op miss is not an error.
    async fn del(&self, key: &str) -> Result<(), OAuthError>;
}

/// In-memory [`SimpleStore`] backed by a `HashMap` under a
/// `std::sync::Mutex`. Suitable for CLIs, single-process servers, and
/// tests; **not** durable across restarts or shared across processes.
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: Mutex<HashMap<String, serde_json::Value>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries currently held. Useful for tests.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait::async_trait]
impl SimpleStore for MemoryStore {
    async fn get(&self, key: &str) -> Result<Option<serde_json::Value>, OAuthError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| OAuthError::Other("MemoryStore mutex poisoned".into()))?;
        Ok(guard.get(key).cloned())
    }

    async fn set(&self, key: &str, value: serde_json::Value) -> Result<(), OAuthError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| OAuthError::Other("MemoryStore mutex poisoned".into()))?;
        guard.insert(key.to_string(), value);
        Ok(())
    }

    async fn del(&self, key: &str) -> Result<(), OAuthError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| OAuthError::Other("MemoryStore mutex poisoned".into()))?;
        guard.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn memory_store_roundtrip() {
        let s = MemoryStore::new();
        assert!(s.get("a").await.unwrap().is_none());

        s.set("a", json!({"v": 1})).await.unwrap();
        assert_eq!(s.get("a").await.unwrap(), Some(json!({"v": 1})));
        assert_eq!(s.len(), 1);

        s.set("a", json!({"v": 2})).await.unwrap();
        assert_eq!(s.get("a").await.unwrap(), Some(json!({"v": 2})));
        assert_eq!(s.len(), 1);

        s.del("a").await.unwrap();
        assert!(s.get("a").await.unwrap().is_none());
        assert_eq!(s.len(), 0);

        // del on miss is not an error.
        s.del("nope").await.unwrap();
    }

    #[tokio::test]
    async fn memory_store_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MemoryStore>();

        // Round-trip through the trait object to confirm object safety.
        let store: std::sync::Arc<dyn SimpleStore> = std::sync::Arc::new(MemoryStore::new());
        store.set("k", json!("v")).await.unwrap();
        assert_eq!(store.get("k").await.unwrap(), Some(json!("v")));
    }
}
