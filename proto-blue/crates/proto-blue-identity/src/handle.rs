//! Handle resolution via DNS TXT records and HTTPS fallback.

use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use futures::future::{self, Either};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig};

use crate::error::IdentityError;

const SUBDOMAIN: &str = "_atproto";
const PREFIX: &str = "did=";
const DNS_PORT: u16 = 53;

/// Resolver for AT Protocol handles to DIDs.
///
/// Uses DNS TXT record lookup (`_atproto.{handle}`) as primary method,
/// with HTTPS fallback (`https://{handle}/.well-known/atproto-did`).
/// Both are raced in parallel for minimum latency.
pub struct HandleResolver {
    timeout: Duration,
    client: reqwest::Client,
    /// Optional backup DNS nameservers. Tried (each in turn) if the
    /// system resolver fails or returns no matching TXT record.
    pub(crate) backup_nameservers: Vec<IpAddr>,
}

impl HandleResolver {
    /// Create a new handle resolver with only the system DNS resolver.
    pub fn new(timeout_ms: u64) -> Self {
        HandleResolver::with_backup_nameservers(timeout_ms, Vec::new())
    }

    /// Create a new handle resolver with backup DNS nameservers.
    ///
    /// `backup_nameservers` are IP addresses (e.g. `8.8.8.8`, `1.1.1.1`)
    /// that will be consulted in order if the system resolver fails or
    /// returns no matching TXT record. Port 53 / UDP is assumed.
    pub fn with_backup_nameservers(timeout_ms: u64, backup_nameservers: Vec<IpAddr>) -> Self {
        HandleResolver {
            timeout: Duration::from_millis(timeout_ms),
            client: reqwest::Client::new(),
            backup_nameservers,
        }
    }

    /// Resolve a handle to a DID by racing DNS and HTTPS lookups in
    /// parallel.
    ///
    /// Both `_atproto.<handle>` TXT record and
    /// `https://<handle>/.well-known/atproto-did` are dispatched
    /// concurrently. Whichever returns a DID first wins; if one returns
    /// `None` first, we wait for the other before reporting `None`.
    /// Latency is therefore `min(dns_rtt, http_rtt)` in the common case
    /// — a meaningful improvement over the previous sequential fallback
    /// when DNS is hung.
    pub async fn resolve(&self, handle: &str) -> Result<Option<String>, IdentityError> {
        let dns_fut = self.resolve_dns(handle);
        let http_fut = self.resolve_http(handle);
        Ok(race_first_some(dns_fut, http_fut).await)
    }

    /// Resolve via DNS TXT record at `_atproto.{handle}`.
    ///
    /// Tries the system resolver first. If that returns no TXT match
    /// (either via a hard error or an empty/multiple-record response),
    /// each configured backup nameserver is consulted in order.
    async fn resolve_dns(&self, handle: &str) -> Option<String> {
        let name = format!("{SUBDOMAIN}.{handle}");

        if let Some(did) = self.dns_lookup_system(&name).await {
            return Some(did);
        }
        for ns in &self.backup_nameservers {
            if let Some(did) = self.dns_lookup_via(&name, *ns).await {
                return Some(did);
            }
        }
        None
    }

    /// DNS TXT lookup via the system resolver (`/etc/resolv.conf` on
    /// Unix, registry on Windows).
    async fn dns_lookup_system(&self, name: &str) -> Option<String> {
        let resolver = TokioResolver::builder_tokio().ok()?.build();
        self.run_txt_lookup(&resolver, name).await
    }

    /// DNS TXT lookup via a specific nameserver IP.
    async fn dns_lookup_via(&self, name: &str, ns: IpAddr) -> Option<String> {
        let group = NameServerConfigGroup::from_ips_clear(
            &[ns],
            DNS_PORT,
            /*trust_negative_responses=*/ true,
        );
        let config = ResolverConfig::from_parts(None, vec![], group);
        let resolver = TokioResolver::builder_with_config(
            config,
            hickory_resolver::name_server::TokioConnectionProvider::default(),
        )
        .build();
        self.run_txt_lookup(&resolver, name).await
    }

    /// Run a TXT lookup against the given resolver with our configured
    /// timeout, extracting exactly-one `did=...` entry.
    async fn run_txt_lookup(&self, resolver: &TokioResolver, name: &str) -> Option<String> {
        let lookup = tokio::time::timeout(self.timeout, resolver.txt_lookup(name))
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
        // The spec requires exactly one matching TXT record. Fewer or
        // more is treated as "not found here" (so the next fallback
        // nameserver or HTTPS can try).
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

/// Race two futures that each resolve to `Option<T>`. Return the first
/// `Some` produced; if both produce `None`, return `None`.
///
/// This is a small building block — extracted so the race semantics
/// can be unit-tested without running real DNS or HTTP. The key
/// property we want is: as soon as *either* future yields `Some`, we
/// return it and drop the other future (no waste). Only if the first
/// to finish is `None` do we block on the second.
async fn race_first_some<T, A, B>(a: A, b: B) -> Option<T>
where
    A: Future<Output = Option<T>>,
    B: Future<Output = Option<T>>,
{
    let a = Box::pin(a);
    let b = Box::pin(b);
    match future::select(a, b).await {
        Either::Left((got, other)) => match got {
            Some(v) => Some(v),
            None => other.await,
        },
        Either::Right((got, other)) => match got {
            Some(v) => Some(v),
            None => other.await,
        },
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

    // ── race_first_some ──────────────────────────────────────────────

    async fn delayed<T: Send + 'static>(ms: u64, v: Option<T>) -> Option<T> {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        v
    }

    #[tokio::test]
    async fn race_returns_fast_some_without_waiting_for_slow() {
        let t = std::time::Instant::now();
        let got = race_first_some(
            delayed(5, Some("fast".to_string())),
            delayed(500, Some("slow".to_string())),
        )
        .await;
        assert_eq!(got.as_deref(), Some("fast"));
        // If we didn't short-circuit we'd wait ~500ms. Generous upper
        // bound to avoid flakiness on slow CI.
        assert!(
            t.elapsed() < Duration::from_millis(200),
            "did not short-circuit"
        );
    }

    #[tokio::test]
    async fn race_returns_fast_some_regardless_of_arg_order() {
        let t = std::time::Instant::now();
        let got = race_first_some(
            delayed(500, Some("slow".to_string())),
            delayed(5, Some("fast".to_string())),
        )
        .await;
        assert_eq!(got.as_deref(), Some("fast"));
        assert!(t.elapsed() < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn race_waits_for_other_when_fast_is_none() {
        // Fast branch returns None; we must still wait for the slow one's
        // Some, not return None prematurely.
        let got = race_first_some(
            delayed::<String>(5, None),
            delayed(50, Some("eventual".to_string())),
        )
        .await;
        assert_eq!(got.as_deref(), Some("eventual"));
    }

    #[tokio::test]
    async fn race_returns_none_when_both_are_none() {
        let got = race_first_some(
            delayed::<&'static str>(5, None),
            delayed::<&'static str>(10, None),
        )
        .await;
        assert_eq!(got, None);
    }

    // ── backup nameservers ──────────────────────────────────────────

    #[test]
    fn backup_nameservers_are_stored() {
        let ips: Vec<IpAddr> = vec!["8.8.8.8".parse().unwrap(), "1.1.1.1".parse().unwrap()];
        let resolver = HandleResolver::with_backup_nameservers(3000, ips.clone());
        assert_eq!(resolver.backup_nameservers, ips);
    }

    #[test]
    fn new_has_no_backup_nameservers() {
        let resolver = HandleResolver::new(3000);
        assert!(resolver.backup_nameservers.is_empty());
    }
}
