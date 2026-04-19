//! OAuth session for making authenticated API requests.
//!
//! Wraps a token set and `DPoP` key to automatically add authorization headers
//! and handle token refresh when needed. HTTP transport is abstracted
//! behind [`proto_blue_common::fetch::FetchHandler`].

use std::sync::{Arc, Mutex};

use proto_blue_common::fetch::{FetchHandler, HttpMethod, HttpRequest, HttpResponse};

use crate::client::{DpopNonceCache, OAuthClient};
use crate::dpop::{DpopKey, build_dpop_proof};
use crate::error::OAuthError;
use crate::types::{OAuthServerMetadata, TokenSet};

/// An authenticated OAuth session.
///
/// Provides methods for making authenticated HTTP requests to AT Protocol
/// resource servers. Automatically handles `DPoP` proof generation and can
/// refresh tokens when they expire.
pub struct OAuthSession {
    /// The current token set.
    token_set: Arc<Mutex<TokenSet>>,
    /// The `DPoP` key for signing proofs.
    dpop_key: DpopKey,
    /// HTTP transport.
    fetcher: Arc<dyn FetchHandler>,
    /// `DPoP` nonce cache (shared with `OAuthClient`).
    dpop_nonces: DpopNonceCache,
    /// Serializes concurrent `/token` refresh requests so N callers
    /// that hit an expired access token at once share a single
    /// round-trip. Held for the duration of the refresh; later callers
    /// wake up to find the token already rotated.
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

impl OAuthSession {
    /// Create a new session from a token set and `DPoP` key, using the
    /// crate's default native fetch handler (`reqwest`).
    #[cfg(all(feature = "fetch-reqwest", not(target_arch = "wasm32")))]
    #[must_use]
    pub fn new(token_set: TokenSet, dpop_key: DpopKey, dpop_nonces: DpopNonceCache) -> Self {
        Self::with_fetch_handler(
            token_set,
            dpop_key,
            dpop_nonces,
            Arc::new(proto_blue_common::fetch::ReqwestFetcher::new()),
        )
    }

    /// Create a new session with a custom `reqwest::Client`.
    ///
    /// Back-compat constructor — wraps the client in a
    /// [`proto_blue_common::fetch::ReqwestFetcher`].
    #[cfg(all(feature = "fetch-reqwest", not(target_arch = "wasm32")))]
    #[must_use]
    pub fn with_http_client(
        token_set: TokenSet,
        dpop_key: DpopKey,
        dpop_nonces: DpopNonceCache,
        http: reqwest::Client,
    ) -> Self {
        Self::with_fetch_handler(
            token_set,
            dpop_key,
            dpop_nonces,
            Arc::new(proto_blue_common::fetch::ReqwestFetcher::from_client(http)),
        )
    }

    /// Create a new session with a user-supplied [`FetchHandler`].
    ///
    /// Primary entry point for wasm and for unit tests.
    pub fn with_fetch_handler(
        token_set: TokenSet,
        dpop_key: DpopKey,
        dpop_nonces: DpopNonceCache,
        fetcher: Arc<dyn FetchHandler>,
    ) -> Self {
        Self {
            token_set: Arc::new(Mutex::new(token_set)),
            dpop_key,
            fetcher,
            dpop_nonces,
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Get the DID of the authenticated user.
    #[must_use]
    pub fn did(&self) -> String {
        self.token_set.lock().unwrap().sub.clone()
    }

    /// Check if the current access token is expired, treating a token
    /// within 10 seconds of expiry as already expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.token_set.lock().unwrap().is_expired(10)
    }

    /// Like [`Self::is_expired`] but jitters the refresh window by
    /// +[0, 30s) so a fleet of sessions with synchronized lifetimes
    /// doesn't stampede the `/token` endpoint.
    #[must_use]
    pub fn is_expired_jittered(&self) -> bool {
        self.token_set.lock().unwrap().is_expired_jittered(10, 30)
    }

    /// Get a clone of the current token set.
    #[must_use]
    pub fn token_set(&self) -> TokenSet {
        self.token_set.lock().unwrap().clone()
    }

    /// Update the token set (e.g., after a refresh).
    pub fn update_token_set(&self, token_set: TokenSet) {
        *self.token_set.lock().unwrap() = token_set;
    }

    /// Refresh the session's tokens using the OAuth client.
    ///
    /// Serialized by an internal mutex so N concurrent callers share a
    /// single `/token` request: later callers block on the lock, then
    /// observe that the access token has already rotated and return
    /// immediately without hitting the network.
    pub async fn refresh(
        &self,
        oauth_client: &OAuthClient,
        server_metadata: &OAuthServerMetadata,
    ) -> Result<(), OAuthError> {
        let before = self.token_set().access_token.clone();
        let _guard = self.refresh_lock.lock().await;
        let current = self.token_set();
        // Double-check after acquiring the lock: if another task just
        // finished a refresh while we were blocked, the access token
        // will have rotated. Skip the network round-trip in that case.
        if current.access_token != before {
            return Ok(());
        }
        let new_token_set = oauth_client
            .refresh_token(server_metadata, &current, &self.dpop_key)
            .await?;
        self.update_token_set(new_token_set);
        Ok(())
    }

    /// Make an authenticated GET request to a resource server.
    ///
    /// Automatically adds `Authorization: DPoP {token}` and `DPoP` proof headers.
    pub async fn get(&self, url: &str) -> Result<HttpResponse, OAuthError> {
        self.request("GET", url, None, None).await
    }

    /// Make an authenticated POST request with a JSON body.
    pub async fn post(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<HttpResponse, OAuthError> {
        let encoded = serde_json::to_vec(body)?;
        self.request("POST", url, Some(encoded), Some("application/json"))
            .await
    }

    /// Make an authenticated HTTP request with an optional body.
    async fn request(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
    ) -> Result<HttpResponse, OAuthError> {
        let access_token = {
            let ts = self.token_set.lock().unwrap();
            ts.access_token.clone()
        };

        // Strip query and fragment for the htu claim
        let htu = strip_query_fragment(url)?;

        // Get cached nonce for this origin
        let nonce = url::Url::parse(url)
            .ok()
            .map(|u| u.origin().ascii_serialization())
            .and_then(|origin| self.dpop_nonces.get(&origin));

        let dpop_proof = build_dpop_proof(
            &self.dpop_key,
            method,
            &htu,
            nonce.as_deref(),
            Some(&access_token),
        )?;

        let http_method = parse_http_method(method)?;
        let mut req = HttpRequest {
            method: http_method,
            url: url.to_string(),
            headers: Default::default(),
            body: body.clone(),
        };
        req = req
            .with_header("authorization", format!("DPoP {access_token}"))
            .with_header("dpop", &dpop_proof);
        if let Some(ct) = content_type {
            req = req.with_header("content-type", ct);
        }

        let resp = self.fetcher.fetch(req).await?;

        // Update DPoP nonce if returned.
        if let Some(nonce_str) = resp.header("dpop-nonce")
            && let Ok(origin) = url::Url::parse(url).map(|u| u.origin().ascii_serialization())
        {
            self.dpop_nonces.set(&origin, nonce_str);
        }

        // If 401 with invalid_token, the caller should refresh and retry.
        if resp.status == 401
            && let Some(auth_str) = resp.header("www-authenticate")
            && auth_str.contains("error=\"invalid_token\"")
            && (auth_str.starts_with("DPoP ") || auth_str.starts_with("Bearer "))
        {
            return Err(OAuthError::RefreshFailed(
                "Access token is invalid, refresh required".into(),
            ));
        }

        Ok(resp)
    }
}

/// Parse an HTTP method string into the common [`HttpMethod`] enum.
fn parse_http_method(method: &str) -> Result<HttpMethod, OAuthError> {
    Ok(match method.to_ascii_uppercase().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "PATCH" => HttpMethod::Patch,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        other => {
            return Err(OAuthError::Other(format!(
                "unsupported HTTP method: {other}"
            )));
        }
    })
}

/// Strip query string and fragment from a URL (for `DPoP` htu claim).
fn strip_query_fragment(url: &str) -> Result<String, OAuthError> {
    let mut parsed = url::Url::parse(url)?;
    parsed.set_query(None);
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_query_and_fragment() {
        let url = "https://bsky.social/xrpc/test?foo=bar#frag";
        let stripped = strip_query_fragment(url).unwrap();
        assert_eq!(stripped, "https://bsky.social/xrpc/test");
    }

    #[test]
    fn strip_preserves_path() {
        let url = "https://bsky.social/xrpc/app.bsky.feed.getTimeline";
        let stripped = strip_query_fragment(url).unwrap();
        assert_eq!(
            stripped,
            "https://bsky.social/xrpc/app.bsky.feed.getTimeline"
        );
    }

    #[test]
    fn parse_http_method_covers_common_verbs() {
        assert_eq!(parse_http_method("GET").unwrap(), HttpMethod::Get);
        assert_eq!(parse_http_method("post").unwrap(), HttpMethod::Post);
        assert_eq!(parse_http_method("DELETE").unwrap(), HttpMethod::Delete);
        assert!(parse_http_method("FOO").is_err());
    }

    #[cfg(all(feature = "fetch-reqwest", not(target_arch = "wasm32")))]
    #[test]
    fn session_token_management() {
        let ts = TokenSet {
            issuer: "https://bsky.social".into(),
            sub: "did:plc:test".into(),
            scope: "atproto".into(),
            access_token: "access-123".into(),
            refresh_token: Some("refresh-456".into()),
            token_type: "DPoP".into(),
            expires_at: Some("2099-01-01T00:00:00Z".into()),
            aud: None,
        };
        let dpop_key = DpopKey::generate().unwrap();
        let session = OAuthSession::new(ts, dpop_key, DpopNonceCache::new());

        assert_eq!(session.did(), "did:plc:test");
        assert!(!session.is_expired());

        let ts = session.token_set();
        assert_eq!(ts.access_token, "access-123");
    }

    #[cfg(all(feature = "fetch-reqwest", not(target_arch = "wasm32")))]
    #[test]
    fn session_update_tokens() {
        let ts = TokenSet {
            issuer: "https://bsky.social".into(),
            sub: "did:plc:test".into(),
            scope: "atproto".into(),
            access_token: "old-token".into(),
            refresh_token: None,
            token_type: "DPoP".into(),
            expires_at: None,
            aud: None,
        };
        let dpop_key = DpopKey::generate().unwrap();
        let session = OAuthSession::new(ts, dpop_key, DpopNonceCache::new());

        let new_ts = TokenSet {
            issuer: "https://bsky.social".into(),
            sub: "did:plc:test".into(),
            scope: "atproto".into(),
            access_token: "new-token".into(),
            refresh_token: Some("refresh".into()),
            token_type: "DPoP".into(),
            expires_at: Some("2099-01-01T00:00:00Z".into()),
            aud: None,
        };
        session.update_token_set(new_ts);

        assert_eq!(session.token_set().access_token, "new-token");
        assert!(session.token_set().refresh_token.is_some());
    }

    #[cfg(all(feature = "fetch-reqwest", not(target_arch = "wasm32")))]
    #[test]
    fn session_expired_detection() {
        let ts = TokenSet {
            issuer: "https://bsky.social".into(),
            sub: "did:plc:test".into(),
            scope: "atproto".into(),
            access_token: "access".into(),
            refresh_token: None,
            token_type: "DPoP".into(),
            expires_at: Some("2020-01-01T00:00:00Z".into()),
            aud: None,
        };
        let dpop_key = DpopKey::generate().unwrap();
        let session = OAuthSession::new(ts, dpop_key, DpopNonceCache::new());
        assert!(session.is_expired());
    }
}
