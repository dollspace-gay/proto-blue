//! DID resolution: did:plc and did:web methods.

use std::sync::Arc;
use std::time::Duration;

use proto_blue_common::fetch::{FetchHandler, HttpRequest};
use proto_blue_common::{
    DidDocument, Service, VerificationMethod, get_did, get_handle, get_pds_endpoint,
    get_signing_key,
};

use crate::cache::DidCache;
use crate::error::IdentityError;
use crate::types::AtprotoData;

const DEFAULT_PLC_URL: &str = "https://plc.directory";

/// Combined DID resolver supporting did:plc and did:web methods.
///
/// HTTP transport is abstracted behind [`FetchHandler`] so the same code
/// drives `reqwest` on native and `fetch()` on
/// `wasm32-unknown-unknown`.
pub struct DidResolver {
    plc_url: String,
    timeout: Duration,
    fetcher: Arc<dyn FetchHandler>,
    cache: Option<Box<dyn DidCache>>,
}

impl DidResolver {
    /// Create a new DID resolver using the crate's default fetch handler.
    ///
    /// With the `fetch-reqwest` feature (default on native), a fresh
    /// `reqwest::Client` is constructed internally. Otherwise the caller
    /// must use [`Self::with_fetch_handler`].
    #[cfg(feature = "fetch-reqwest")]
    pub fn new(plc_url: Option<&str>, timeout_ms: u64, cache: Option<Box<dyn DidCache>>) -> Self {
        Self::with_fetch_handler(
            plc_url,
            timeout_ms,
            cache,
            Arc::new(proto_blue_common::fetch::ReqwestFetcher::new()),
        )
    }

    /// Create a new DID resolver with a user-supplied [`FetchHandler`].
    ///
    /// Primary entry point for wasm and for unit tests that want to mock
    /// out the PLC directory / `did:web` hosts.
    pub fn with_fetch_handler(
        plc_url: Option<&str>,
        timeout_ms: u64,
        cache: Option<Box<dyn DidCache>>,
        fetcher: Arc<dyn FetchHandler>,
    ) -> Self {
        DidResolver {
            plc_url: plc_url.unwrap_or(DEFAULT_PLC_URL).to_string(),
            timeout: Duration::from_millis(timeout_ms),
            fetcher,
            cache,
        }
    }

    /// Resolve a DID to its DID document, with caching.
    pub async fn resolve(
        &self,
        did: &str,
        force_refresh: bool,
    ) -> Result<Option<DidDocument>, IdentityError> {
        // Check cache first
        if !force_refresh {
            if let Some(cache) = &self.cache {
                if let Some(cached) = cache.check_cache(did).await {
                    if !cached.expired {
                        if cached.stale {
                            // Background refresh — just return stale data
                            // In a full impl, we'd spawn a task to refresh
                        }
                        return Ok(Some(cached.doc));
                    }
                }
            }
        }

        // Resolve fresh
        let doc = self.resolve_no_cache(did).await?;

        // Update cache
        if let Some(doc) = &doc {
            if let Some(cache) = &self.cache {
                cache.cache_did(did, doc.clone()).await;
            }
        } else if let Some(cache) = &self.cache {
            cache.clear_entry(did).await;
        }

        Ok(doc)
    }

    /// Resolve a DID, returning an error if not found.
    pub async fn ensure_resolve(
        &self,
        did: &str,
        force_refresh: bool,
    ) -> Result<DidDocument, IdentityError> {
        self.resolve(did, force_refresh)
            .await?
            .ok_or_else(|| IdentityError::DidNotFound(did.to_string()))
    }

    /// Resolve a DID and extract AT Protocol-specific data.
    pub async fn resolve_atproto_data(
        &self,
        did: &str,
        force_refresh: bool,
    ) -> Result<AtprotoData, IdentityError> {
        let doc = self.ensure_resolve(did, force_refresh).await?;
        ensure_atp_document(&doc)
    }

    /// Resolve without caching.
    pub async fn resolve_no_cache(&self, did: &str) -> Result<Option<DidDocument>, IdentityError> {
        let raw = self.resolve_no_check(did).await?;
        match raw {
            None => Ok(None),
            Some(doc) => {
                validate_did_doc(did, &doc)?;
                Ok(Some(doc))
            }
        }
    }

    /// Resolve without validation or caching — dispatches to the appropriate method.
    async fn resolve_no_check(&self, did: &str) -> Result<Option<DidDocument>, IdentityError> {
        if !did.starts_with("did:") {
            return Err(IdentityError::PoorlyFormattedDid(did.to_string()));
        }

        let method_sep = did[4..]
            .find(':')
            .ok_or_else(|| IdentityError::PoorlyFormattedDid(did.to_string()))?;
        let method = &did[4..4 + method_sep];

        match method {
            "plc" => self.resolve_plc(did).await,
            "web" => self.resolve_web(did).await,
            // did:key is fully inline — no network call, the public key
            // is encoded directly in the identifier. We synthesize a
            // minimal DID document containing only the `#atproto` signing
            // key. It has no `alsoKnownAs` and no service endpoints, so
            // `ensure_atp_document` will later fail with MissingHandle or
            // MissingPds — which is correct: did:key identifiers cannot
            // participate in the atproto network, only sign payloads.
            "key" => Ok(Some(synthesize_did_key_doc(did)?)),
            _ => Err(IdentityError::UnsupportedDidMethod(did.to_string())),
        }
    }

    /// Issue an HTTP GET via the configured fetcher, enforcing the
    /// resolver's per-call timeout at the future boundary. The fetch trait
    /// deliberately does not carry per-request timeout fields — keeping
    /// the trait minimal means a single place (here) wraps every call.
    async fn get_json(
        &self,
        url: &str,
    ) -> Result<proto_blue_common::fetch::HttpResponse, IdentityError> {
        let req = HttpRequest::get(url)
            .with_header("accept", "application/did+ld+json,application/json");
        let fut = self.fetcher.fetch(req);
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(IdentityError::Fetch(e)),
            Err(_) => Err(IdentityError::Timeout),
        }
    }

    /// Resolve a did:plc DID via the PLC directory.
    async fn resolve_plc(&self, did: &str) -> Result<Option<DidDocument>, IdentityError> {
        let url = format!("{}/{}", self.plc_url, did);
        let response = self.get_json(&url).await?;

        if response.status == 404 {
            return Ok(None);
        }

        if !response.is_success() {
            return Err(IdentityError::Other(format!(
                "PLC directory returned status {}",
                response.status
            )));
        }

        let doc: DidDocument = serde_json::from_slice(&response.body)?;
        Ok(Some(doc))
    }

    /// Resolve a did:web DID via HTTPS.
    async fn resolve_web(&self, did: &str) -> Result<Option<DidDocument>, IdentityError> {
        let parts: Vec<&str> = did.split(':').collect();
        if parts.len() < 3 {
            return Err(IdentityError::PoorlyFormattedDid(did.to_string()));
        }

        // did:web:example.com -> https://example.com/.well-known/did.json
        // did:web:example.com:path:to -> unsupported in AT Protocol
        if parts.len() > 3 {
            return Err(IdentityError::UnsupportedDidWebPath(did.to_string()));
        }

        let hostname = percent_decode(parts[2]);

        let scheme = if hostname == "localhost" || hostname.starts_with("localhost:") {
            "http"
        } else {
            "https"
        };

        let url = format!("{scheme}://{hostname}/.well-known/did.json");

        // did:web intentionally swallows every non-success response (404,
        // offline host, TLS error, timeout) and returns `None` — the
        // spec treats "not found" as an expected outcome, not a hard
        // error. Only JSON-shape failures get propagated.
        match self.get_json(&url).await {
            Ok(resp) if resp.is_success() => match serde_json::from_slice(&resp.body) {
                Ok(doc) => Ok(Some(doc)),
                Err(e) => Err(IdentityError::Json(e)),
            },
            _ => Ok(None),
        }
    }
}

/// Synthesize a DID document for a `did:key:z...` identifier.
///
/// `did:key` is a self-contained DID method: the public key is encoded
/// directly in the identifier (multibase-encoded multicodec + compressed
/// point). We don't fetch anything — we just validate the encoding via
/// `proto_blue_crypto::parse_did_key` and return a minimal doc whose
/// only verification method is the embedded signing key.
///
/// The returned document has:
/// - `id`: the full did:key identifier
/// - a single `#atproto` verification method with `publicKeyMultibase`
///   equal to the `z...` portion of the DID
/// - no `alsoKnownAs` and no `service` entries
///
/// Callers that pass such a document to `ensure_atp_document` will get a
/// `MissingHandle` or `MissingPds` error — did:key identifiers cannot
/// host an atproto repo, only sign arbitrary payloads.
fn synthesize_did_key_doc(did: &str) -> Result<DidDocument, IdentityError> {
    // Validate the encoding. `parse_did_key` rejects malformed or wrong-
    // prefix multibase blobs.
    proto_blue_crypto::parse_did_key(did)
        .map_err(|e| IdentityError::PoorlyFormattedDid(format!("{did}: {e}")))?;

    // The `z...` multikey portion is everything after `did:key:`.
    let multikey = did
        .strip_prefix("did:key:")
        .ok_or_else(|| IdentityError::PoorlyFormattedDid(did.to_string()))?
        .to_string();

    Ok(DidDocument {
        id: did.to_string(),
        also_known_as: Vec::new(),
        verification_method: vec![VerificationMethod {
            id: format!("{did}#atproto"),
            method_type: "Multikey".to_string(),
            controller: did.to_string(),
            public_key_multibase: Some(multikey),
        }],
        service: Vec::<Service>::new(),
    })
}

/// Simple percent-decoding for did:web hostnames.
fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().and_then(hex_val);
            let lo = chars.next().and_then(hex_val);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push((h << 4 | l) as char);
            }
        } else {
            result.push(b as char);
        }
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Validate that a DID document has the expected structure.
fn validate_did_doc(did: &str, doc: &DidDocument) -> Result<(), IdentityError> {
    if doc.id != did {
        return Err(IdentityError::PoorlyFormattedDidDocument {
            did: did.to_string(),
        });
    }
    Ok(())
}

/// Extract and validate all AT Protocol data from a DID document.
pub fn ensure_atp_document(doc: &DidDocument) -> Result<AtprotoData, IdentityError> {
    let did = get_did(doc).to_string();

    let signing_key =
        get_signing_key(doc).ok_or_else(|| IdentityError::MissingSigningKey(did.clone()))?;
    let signing_key_str = format!("did:key:{}", signing_key.public_key_multibase);

    let handle = get_handle(doc)
        .ok_or_else(|| IdentityError::MissingHandle(did.clone()))?
        .to_string();

    let pds = get_pds_endpoint(doc).ok_or_else(|| IdentityError::MissingPds(did.clone()))?;

    Ok(AtprotoData {
        did,
        signing_key: signing_key_str,
        handle,
        pds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_blue_common::parse_did_document;

    #[test]
    fn ensure_atp_document_valid() {
        let json = r##"{
            "id": "did:plc:testuser123",
            "alsoKnownAs": ["at://alice.bsky.social"],
            "verificationMethod": [{
                "id": "#atproto",
                "type": "Multikey",
                "controller": "did:plc:testuser123",
                "publicKeyMultibase": "zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"
            }],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://bsky.social"
            }]
        }"##;
        let doc = parse_did_document(json).unwrap();
        let data = ensure_atp_document(&doc).unwrap();
        assert_eq!(data.did, "did:plc:testuser123");
        assert_eq!(data.handle, "alice.bsky.social");
        assert_eq!(data.pds, "https://bsky.social");
        assert!(data.signing_key.starts_with("did:key:z"));
    }

    #[test]
    fn ensure_atp_document_missing_key() {
        let json = r##"{
            "id": "did:plc:test",
            "alsoKnownAs": ["at://test.bsky.social"],
            "verificationMethod": [],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://bsky.social"
            }]
        }"##;
        let doc = parse_did_document(json).unwrap();
        let err = ensure_atp_document(&doc).unwrap_err();
        assert!(matches!(err, IdentityError::MissingSigningKey(_)));
    }

    #[test]
    fn ensure_atp_document_missing_handle() {
        let json = r##"{
            "id": "did:plc:test",
            "alsoKnownAs": [],
            "verificationMethod": [{
                "id": "#atproto",
                "type": "Multikey",
                "controller": "did:plc:test",
                "publicKeyMultibase": "zAbc123"
            }],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://bsky.social"
            }]
        }"##;
        let doc = parse_did_document(json).unwrap();
        let err = ensure_atp_document(&doc).unwrap_err();
        assert!(matches!(err, IdentityError::MissingHandle(_)));
    }

    #[test]
    fn ensure_atp_document_missing_pds() {
        let json = r##"{
            "id": "did:plc:test",
            "alsoKnownAs": ["at://test.bsky.social"],
            "verificationMethod": [{
                "id": "#atproto",
                "type": "Multikey",
                "controller": "did:plc:test",
                "publicKeyMultibase": "zAbc123"
            }],
            "service": []
        }"##;
        let doc = parse_did_document(json).unwrap();
        let err = ensure_atp_document(&doc).unwrap_err();
        assert!(matches!(err, IdentityError::MissingPds(_)));
    }

    #[test]
    fn validate_did_doc_mismatch() {
        let json = r##"{
            "id": "did:plc:other",
            "verificationMethod": [],
            "service": []
        }"##;
        let doc = parse_did_document(json).unwrap();
        let err = validate_did_doc("did:plc:expected", &doc).unwrap_err();
        assert!(matches!(
            err,
            IdentityError::PoorlyFormattedDidDocument { .. }
        ));
    }

    #[test]
    fn did_resolver_parses_method() {
        // Test method parsing without making HTTP requests
        let did = "did:plc:abc123";
        assert!(did.starts_with("did:"));
        let method_sep = did[4..].find(':').unwrap();
        assert_eq!(&did[4..4 + method_sep], "plc");

        let did_web = "did:web:example.com";
        let method_sep = did_web[4..].find(':').unwrap();
        assert_eq!(&did_web[4..4 + method_sep], "web");
    }

    #[test]
    fn did_web_url_construction() {
        // Test the URL construction logic for did:web
        let did = "did:web:example.com";
        let parts: Vec<&str> = did.split(':').collect();
        assert_eq!(parts.len(), 3);
        let hostname = parts[2];
        let url = format!("https://{hostname}/.well-known/did.json");
        assert_eq!(url, "https://example.com/.well-known/did.json");
    }

    #[test]
    fn did_web_localhost_uses_http() {
        let did = "did:web:localhost";
        let parts: Vec<&str> = did.split(':').collect();
        let hostname = parts[2];
        let scheme = if hostname == "localhost" || hostname.starts_with("localhost:") {
            "http"
        } else {
            "https"
        };
        assert_eq!(scheme, "http");
        let url = format!("{scheme}://{hostname}/.well-known/did.json");
        assert_eq!(url, "http://localhost/.well-known/did.json");
    }

    // ── did:key resolution ───────────────────────────────────────────

    /// A real did:key produced by proto-blue-crypto. This one appears in
    /// the W3C test vectors as well, so the multikey blob is known-good.
    const SAMPLE_DID_KEY: &str = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";

    #[test]
    fn did_key_synthesizes_minimal_document() {
        let doc = synthesize_did_key_doc(SAMPLE_DID_KEY).unwrap();
        assert_eq!(doc.id, SAMPLE_DID_KEY);
        assert!(doc.also_known_as.is_empty());
        assert!(doc.service.is_empty());
        assert_eq!(doc.verification_method.len(), 1);
        let vm = &doc.verification_method[0];
        assert_eq!(vm.method_type, "Multikey");
        assert_eq!(vm.controller, SAMPLE_DID_KEY);
        let mb = vm.public_key_multibase.as_deref().unwrap();
        assert!(mb.starts_with('z'));
        // The multikey must be exactly the portion after `did:key:`.
        assert_eq!(mb, &SAMPLE_DID_KEY["did:key:".len()..]);
    }

    #[test]
    fn did_key_resolver_returns_synthesized_doc() {
        let resolver = DidResolver::new(None, 1000, None);
        let resolve = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(resolver.resolve_no_check(SAMPLE_DID_KEY));
        let doc = resolve.unwrap().expect("synthesized doc");
        assert_eq!(doc.id, SAMPLE_DID_KEY);
    }

    #[test]
    fn did_key_malformed_is_rejected() {
        // Missing `z` multibase prefix — parse_did_key will reject.
        let bad = "did:key:Q3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
        let err = synthesize_did_key_doc(bad).unwrap_err();
        assert!(matches!(err, IdentityError::PoorlyFormattedDid(_)));
    }

    #[test]
    fn did_key_ensure_atp_document_fails_with_missing_handle() {
        // The synthesized did:key document has no alsoKnownAs, so the
        // atproto-data extractor must surface that as MissingHandle.
        let doc = synthesize_did_key_doc(SAMPLE_DID_KEY).unwrap();
        let err = ensure_atp_document(&doc).unwrap_err();
        assert!(matches!(err, IdentityError::MissingHandle(_)));
    }
}
