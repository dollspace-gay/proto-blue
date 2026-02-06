//! OAuth session for making authenticated API requests.
//!
//! Wraps a token set and DPoP key to automatically add authorization headers
//! and handle token refresh when needed.

use std::sync::{Arc, Mutex};

use crate::client::{DpopNonceCache, OAuthClient};
use crate::dpop::{DpopKey, build_dpop_proof};
use crate::error::OAuthError;
use crate::types::{OAuthServerMetadata, TokenSet};

/// An authenticated OAuth session.
///
/// Provides methods for making authenticated HTTP requests to AT Protocol
/// resource servers. Automatically handles DPoP proof generation and
/// can refresh tokens when they expire.
pub struct OAuthSession {
    /// The current token set.
    token_set: Arc<Mutex<TokenSet>>,
    /// The DPoP key for signing proofs.
    dpop_key: DpopKey,
    /// The HTTP client.
    http: reqwest::Client,
    /// DPoP nonce cache (shared with OAuthClient).
    dpop_nonces: DpopNonceCache,
}

impl OAuthSession {
    /// Create a new session from a token set and DPoP key.
    pub fn new(token_set: TokenSet, dpop_key: DpopKey, dpop_nonces: DpopNonceCache) -> Self {
        OAuthSession {
            token_set: Arc::new(Mutex::new(token_set)),
            dpop_key,
            http: reqwest::Client::new(),
            dpop_nonces,
        }
    }

    /// Create a new session with a custom HTTP client.
    pub fn with_http_client(
        token_set: TokenSet,
        dpop_key: DpopKey,
        dpop_nonces: DpopNonceCache,
        http: reqwest::Client,
    ) -> Self {
        OAuthSession {
            token_set: Arc::new(Mutex::new(token_set)),
            dpop_key,
            http,
            dpop_nonces,
        }
    }

    /// Get the DID of the authenticated user.
    pub fn did(&self) -> String {
        self.token_set.lock().unwrap().sub.clone()
    }

    /// Check if the current access token is expired.
    pub fn is_expired(&self) -> bool {
        self.token_set.lock().unwrap().is_expired(10)
    }

    /// Get a clone of the current token set.
    pub fn token_set(&self) -> TokenSet {
        self.token_set.lock().unwrap().clone()
    }

    /// Update the token set (e.g., after a refresh).
    pub fn update_token_set(&self, token_set: TokenSet) {
        *self.token_set.lock().unwrap() = token_set;
    }

    /// Refresh the session's tokens using the OAuth client.
    pub async fn refresh(
        &self,
        oauth_client: &OAuthClient,
        server_metadata: &OAuthServerMetadata,
    ) -> Result<(), OAuthError> {
        let current = self.token_set();
        let new_token_set = oauth_client
            .refresh_token(server_metadata, &current, &self.dpop_key)
            .await?;
        self.update_token_set(new_token_set);
        Ok(())
    }

    /// Make an authenticated GET request to a resource server.
    ///
    /// Automatically adds `Authorization: DPoP {token}` and `DPoP` proof headers.
    pub async fn get(&self, url: &str) -> Result<reqwest::Response, OAuthError> {
        self.request("GET", url, None).await
    }

    /// Make an authenticated POST request with a JSON body.
    pub async fn post(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, OAuthError> {
        self.request("POST", url, Some(body)).await
    }

    /// Make an authenticated HTTP request.
    async fn request(
        &self,
        method: &str,
        url: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<reqwest::Response, OAuthError> {
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

        let mut req = match method {
            "GET" => self.http.get(url),
            "POST" => self.http.post(url),
            "PUT" => self.http.put(url),
            "DELETE" => self.http.delete(url),
            _ => self.http.request(
                method
                    .parse()
                    .map_err(|e| OAuthError::Other(format!("Invalid HTTP method: {e}")))?,
                url,
            ),
        };

        req = req
            .header("Authorization", format!("DPoP {access_token}"))
            .header("DPoP", &dpop_proof);

        if let Some(body) = body {
            req = req.json(body);
        }

        let resp = req.send().await?;

        // Update DPoP nonce if returned
        if let Some(nonce_header) = resp.headers().get("dpop-nonce") {
            if let Ok(nonce_str) = nonce_header.to_str() {
                if let Ok(origin) = url::Url::parse(url).map(|u| u.origin().ascii_serialization()) {
                    self.dpop_nonces.set(&origin, nonce_str);
                }
            }
        }

        // If 401 with invalid_token, the caller should refresh and retry
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            if let Some(www_auth) = resp.headers().get("www-authenticate") {
                if let Ok(auth_str) = www_auth.to_str() {
                    if auth_str.contains("error=\"invalid_token\"")
                        && (auth_str.starts_with("DPoP ") || auth_str.starts_with("Bearer "))
                    {
                        return Err(OAuthError::RefreshFailed(
                            "Access token is invalid, refresh required".into(),
                        ));
                    }
                }
            }
        }

        Ok(resp)
    }
}

/// Strip query string and fragment from a URL (for DPoP htu claim).
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
    fn session_token_management() {
        let ts = TokenSet {
            issuer: "https://bsky.social".into(),
            sub: "did:plc:test".into(),
            scope: "atproto".into(),
            access_token: "access-123".into(),
            refresh_token: Some("refresh-456".into()),
            token_type: "DPoP".into(),
            expires_at: Some("2099-01-01T00:00:00Z".into()),
        };
        let dpop_key = DpopKey::generate().unwrap();
        let session = OAuthSession::new(ts, dpop_key, DpopNonceCache::new());

        assert_eq!(session.did(), "did:plc:test");
        assert!(!session.is_expired());

        let ts = session.token_set();
        assert_eq!(ts.access_token, "access-123");
    }

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
        };
        session.update_token_set(new_ts);

        assert_eq!(session.token_set().access_token, "new-token");
        assert!(session.token_set().refresh_token.is_some());
    }

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
        };
        let dpop_key = DpopKey::generate().unwrap();
        let session = OAuthSession::new(ts, dpop_key, DpopNonceCache::new());
        assert!(session.is_expired());
    }
}
