//! Handle resolution via DNS TXT records and HTTPS fallback.

use std::time::Duration;

use crate::error::IdentityError;

const SUBDOMAIN: &str = "_atproto";
const PREFIX: &str = "did=";

/// Resolver for AT Protocol handles to DIDs.
///
/// Uses DNS TXT record lookup (`_atproto.{handle}`) as primary method,
/// with HTTPS fallback (`https://{handle}/.well-known/atproto-did`).
pub struct HandleResolver {
    timeout: Duration,
    client: reqwest::Client,
}

impl HandleResolver {
    /// Create a new handle resolver.
    pub fn new(timeout_ms: u64) -> Self {
        HandleResolver {
            timeout: Duration::from_millis(timeout_ms),
            client: reqwest::Client::new(),
        }
    }

    /// Resolve a handle to a DID.
    ///
    /// Tries DNS TXT lookup first, then falls back to HTTPS.
    pub async fn resolve(&self, handle: &str) -> Result<Option<String>, IdentityError> {
        // Try DNS first
        if let Some(did) = self.resolve_dns(handle).await {
            return Ok(Some(did));
        }

        // Fall back to HTTPS
        if let Some(did) = self.resolve_http(handle).await {
            return Ok(Some(did));
        }

        Ok(None)
    }

    /// Resolve via DNS TXT record at `_atproto.{handle}`.
    async fn resolve_dns(&self, handle: &str) -> Option<String> {
        let name = format!("{SUBDOMAIN}.{handle}");

        // Use hickory-resolver for DNS TXT lookups
        let resolver = hickory_resolver::Resolver::builder_tokio().ok()?.build();

        let lookup = tokio::time::timeout(self.timeout, resolver.txt_lookup(name.as_str()))
            .await
            .ok()?
            .ok()?;

        let mut results = Vec::new();
        for record in lookup.iter() {
            let txt = record.to_string();
            if let Some(did) = txt.strip_prefix(PREFIX) {
                results.push(did.to_string());
            }
        }

        // Must be exactly one matching TXT record
        if results.len() == 1 {
            Some(results.remove(0))
        } else {
            None
        }
    }

    /// Resolve via HTTPS at `https://{handle}/.well-known/atproto-did`.
    async fn resolve_http(&self, handle: &str) -> Option<String> {
        let url = format!("https://{handle}/.well-known/atproto-did");

        let response = self
            .client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await
            .ok()?;

        if !response.status().is_success() {
            return None;
        }

        let text = response.text().await.ok()?;
        let did = text.lines().next()?.trim();

        if did.starts_with("did:") {
            Some(did.to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_name_construction() {
        let handle = "alice.bsky.social";
        let name = format!("{SUBDOMAIN}.{handle}");
        assert_eq!(name, "_atproto.alice.bsky.social");
    }

    #[test]
    fn http_url_construction() {
        let handle = "alice.bsky.social";
        let url = format!("https://{handle}/.well-known/atproto-did");
        assert_eq!(url, "https://alice.bsky.social/.well-known/atproto-did");
    }

    #[test]
    fn parse_dns_result_valid() {
        let txt = "did=did:plc:abc123";
        assert!(txt.starts_with(PREFIX));
        let did = &txt[PREFIX.len()..];
        assert_eq!(did, "did:plc:abc123");
    }

    #[test]
    fn parse_http_response() {
        let text = "did:plc:abc123\n";
        let did = text.lines().next().unwrap().trim();
        assert_eq!(did, "did:plc:abc123");
        assert!(did.starts_with("did:"));
    }

    #[test]
    fn parse_http_response_not_did() {
        let text = "not-a-did\n";
        let did = text.lines().next().unwrap().trim();
        assert!(!did.starts_with("did:"));
    }
}
