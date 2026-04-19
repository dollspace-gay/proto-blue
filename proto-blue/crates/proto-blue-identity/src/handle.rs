//! Handle resolution via DNS TXT records and HTTPS fallback.
//!
//! DNS resolution is native-only (powered by `hickory-resolver`) and lives
//! behind the `dns` feature (on by default). The HTTPS `.well-known`
//! fallback uses [`proto_blue_common::fetch::FetchHandler`] and therefore
//! works on any target the chosen fetch backend supports — including
//! `wasm32-unknown-unknown`, where handle resolution degrades gracefully
//! to HTTPS-only (the behaviour matching what browsers can actually do).

use std::sync::Arc;
use std::time::Duration;

use proto_blue_common::fetch::{FetchHandler, HttpRequest};

use crate::error::IdentityError;

#[cfg(feature = "dns")]
use std::future::Future;
#[cfg(feature = "dns")]
use std::net::IpAddr;
#[cfg(feature = "dns")]
use futures::future::{self, Either};
#[cfg(feature = "dns")]
use hickory_resolver::TokioResolver;
#[cfg(feature = "dns")]
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig};

#[cfg(feature = "dns")]
const SUBDOMAIN: &str = "_atproto";
#[cfg(feature = "dns")]
const PREFIX: &str = "did=";
#[cfg(feature = "dns")]
const DNS_PORT: u16 = 53;

/// Resolver for AT Protocol handles to DIDs.
///
/// The spec supports two discovery methods:
/// - a DNS TXT record at `_atproto.<handle>` (native only, `dns` feature),
/// - an HTTPS `.well-known/atproto-did` file at the handle's host.
///
/// Both paths are raced in parallel for minimum latency. On
/// `wasm32-unknown-unknown` the DNS path is compiled out; only the HTTPS
/// path runs. That matches the TS SDK's browser behaviour.
pub struct HandleResolver {
    timeout: Duration,
    fetcher: Arc<dyn FetchHandler>,
    /// Optional backup DNS nameservers. Tried (each in turn) if the
    /// system resolver fails or returns no matching TXT record.
    #[cfg(feature = "dns")]
    pub(crate) backup_nameservers: Vec<IpAddr>,
}

impl HandleResolver {
    /// Create a new handle resolver with only the system DNS resolver (on
    /// native) and the default fetch backend.
    #[cfg(feature = "fetch-reqwest")]
    pub fn new(timeout_ms: u64) -> Self {
        Self::with_fetch_handler(
            timeout_ms,
            Arc::new(proto_blue_common::fetch::ReqwestFetcher::new()),
        )
    }

    /// Create a new handle resolver with backup DNS nameservers.
    ///
    /// `backup_nameservers` are IP addresses (e.g. `8.8.8.8`, `1.1.1.1`)
    /// that will be consulted in order if the system resolver fails or
    /// returns no matching TXT record. Port 53 / UDP is assumed.
    #[cfg(all(feature = "fetch-reqwest", feature = "dns"))]
    pub fn with_backup_nameservers(timeout_ms: u64, backup_nameservers: Vec<IpAddr>) -> Self {
        HandleResolver {
            timeout: Duration::from_millis(timeout_ms),
            fetcher: Arc::new(proto_blue_common::fetch::ReqwestFetcher::new()),
            backup_nameservers,
        }
    }

    /// Create a new handle resolver with a user-supplied [`FetchHandler`].
    pub fn with_fetch_handler(timeout_ms: u64, fetcher: Arc<dyn FetchHandler>) -> Self {
        HandleResolver {
            timeout: Duration::from_millis(timeout_ms),
            fetcher,
            #[cfg(feature = "dns")]
            backup_nameservers: Vec::new(),
        }
    }

    /// Set backup DNS nameservers (native-only).
    #[cfg(feature = "dns")]
    pub fn set_backup_nameservers(&mut self, nameservers: Vec<IpAddr>) {
        self.backup_nameservers = nameservers;
    }

    /// Resolve a handle to a DID by racing DNS (native-only) and HTTPS
    /// lookups in parallel.
    ///
    /// On native with the `dns` feature, both `_atproto.<handle>` TXT
    /// lookup and `https://<handle>/.well-known/atproto-did` are
    /// dispatched concurrently; whichever returns a DID first wins. If
    /// either returns `None` first, we wait for the other before
    /// reporting `None`. On wasm (no DNS), only the HTTPS path runs.
    pub async fn resolve(&self, handle: &str) -> Result<Option<String>, IdentityError> {
        #[cfg(feature = "dns")]
        {
            let dns_fut = self.resolve_dns(handle);
            let http_fut = self.resolve_http(handle);
            Ok(race_first_some(dns_fut, http_fut).await)
        }
        #[cfg(not(feature = "dns"))]
        {
            Ok(self.resolve_http(handle).await)
        }
    }

    /// Resolve via DNS TXT record at `_atproto.{handle}`.
    ///
    /// Tries the system resolver first. If that returns no TXT match
    /// (either via a hard error or an empty/multiple-record response),
    /// each configured backup nameserver is consulted in order.
    #[cfg(feature = "dns")]
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
    #[cfg(feature = "dns")]
    async fn dns_lookup_system(&self, name: &str) -> Option<String> {
        let resolver = TokioResolver::builder_tokio().ok()?.build();
        self.run_txt_lookup(&resolver, name).await
    }

    /// DNS TXT lookup via a specific nameserver IP.
    #[cfg(feature = "dns")]
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
    #[cfg(feature = "dns")]
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
    ///
    /// This path works on any [`FetchHandler`]-supported target,
    /// including `wasm32-unknown-unknown`.
    async fn resolve_http(&self, handle: &str) -> Option<String> {
        let url = format!("https://{handle}/.well-known/atproto-did");
        let req = HttpRequest::get(url);

        let fut = self.fetcher.fetch(req);
        let response = tokio::time::timeout(self.timeout, fut).await.ok()?.ok()?;

        if !response.is_success() {
            return None;
        }

        let text = std::str::from_utf8(&response.body).ok()?;
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
/// This is a small building block — extracted so the race semantics can be
/// unit-tested without running real DNS or HTTP. The key property we want
/// is: as soon as *either* future yields `Some`, we return it and drop the
/// other future (no waste). Only if the first to finish is `None` do we
/// block on the second.
#[cfg(feature = "dns")]
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

    #[cfg(feature = "dns")]
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

    #[cfg(feature = "dns")]
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

    #[cfg(feature = "dns")]
    async fn delayed<T: Send + 'static>(ms: u64, v: Option<T>) -> Option<T> {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        v
    }

    #[cfg(feature = "dns")]
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

    #[cfg(feature = "dns")]
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

    #[cfg(feature = "dns")]
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

    #[cfg(feature = "dns")]
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

    #[cfg(all(feature = "dns", feature = "fetch-reqwest"))]
    #[test]
    fn backup_nameservers_are_stored() {
        let ips: Vec<IpAddr> = vec!["8.8.8.8".parse().unwrap(), "1.1.1.1".parse().unwrap()];
        let resolver = HandleResolver::with_backup_nameservers(3000, ips.clone());
        assert_eq!(resolver.backup_nameservers, ips);
    }

    #[cfg(all(feature = "dns", feature = "fetch-reqwest"))]
    #[test]
    fn new_has_no_backup_nameservers() {
        let resolver = HandleResolver::new(3000);
        assert!(resolver.backup_nameservers.is_empty());
    }
}
