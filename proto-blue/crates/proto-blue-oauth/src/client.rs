//! OAuth 2.0 client for AT Protocol.
//!
//! Implements the full OAuth authorization code flow with PKCE, DPoP, and PAR.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use url::Url;

use crate::dpop::{DpopKey, build_dpop_proof};
use crate::error::OAuthError;
use crate::pkce::generate_pkce;
use crate::types::{
    AuthState, OAuthClientMetadata, OAuthServerMetadata, OAuthTokenResponse, ParResponse, TokenSet,
};

/// Per-origin DPoP nonce cache.
#[derive(Debug, Clone, Default)]
pub struct DpopNonceCache {
    nonces: Arc<Mutex<HashMap<String, String>>>,
}

impl DpopNonceCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the cached nonce for an origin.
    pub fn get(&self, origin: &str) -> Option<String> {
        self.nonces.lock().ok()?.get(origin).cloned()
    }

    /// Store a nonce for an origin.
    pub fn set(&self, origin: &str, nonce: &str) {
        if let Ok(mut map) = self.nonces.lock() {
            map.insert(origin.to_string(), nonce.to_string());
        }
    }
}

/// OAuth 2.0 client for AT Protocol.
///
/// Handles the full authorization code flow:
/// 1. Discover authorization server metadata
/// 2. Build authorization URL (with PKCE + DPoP, optional PAR)
/// 3. Exchange authorization code for tokens
/// 4. Refresh tokens when they expire
/// 5. Revoke tokens on sign-out
pub struct OAuthClient {
    /// Client metadata (client_id, redirect_uris, etc.).
    pub client_metadata: OAuthClientMetadata,
    /// HTTP client for making requests.
    http: reqwest::Client,
    /// DPoP nonce cache (per-origin).
    dpop_nonces: DpopNonceCache,
}

impl OAuthClient {
    /// Create a new OAuth client.
    pub fn new(client_metadata: OAuthClientMetadata) -> Self {
        OAuthClient {
            client_metadata,
            http: reqwest::Client::new(),
            dpop_nonces: DpopNonceCache::new(),
        }
    }

    /// Create a new OAuth client with a custom HTTP client.
    pub fn with_http_client(client_metadata: OAuthClientMetadata, http: reqwest::Client) -> Self {
        OAuthClient {
            client_metadata,
            http,
            dpop_nonces: DpopNonceCache::new(),
        }
    }

    /// Discover authorization server metadata from an issuer URL.
    ///
    /// Fetches `{issuer}/.well-known/oauth-authorization-server` per RFC 8414.
    pub async fn discover_server(&self, issuer: &str) -> Result<OAuthServerMetadata, OAuthError> {
        let url = format!(
            "{}/.well-known/oauth-authorization-server",
            issuer.trim_end_matches('/')
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await?
            .error_for_status()
            .map_err(OAuthError::Http)?;
        let metadata: OAuthServerMetadata = resp.json().await?;

        // Verify issuer matches
        let expected_issuer = issuer.trim_end_matches('/');
        let actual_issuer = metadata.issuer.trim_end_matches('/');
        if expected_issuer != actual_issuer {
            return Err(OAuthError::IssuerMismatch {
                expected: expected_issuer.to_string(),
                actual: actual_issuer.to_string(),
            });
        }

        Ok(metadata)
    }

    /// Build an authorization URL for the user to visit.
    ///
    /// Returns `(authorization_url, auth_state)`. The caller must store the `AuthState`
    /// (keyed by the `state` query parameter) to complete the flow in `callback()`.
    pub async fn authorize(
        &self,
        server_metadata: &OAuthServerMetadata,
    ) -> Result<(Url, AuthState), OAuthError> {
        let pkce = generate_pkce();
        let dpop_key = DpopKey::generate()?;

        // Generate state parameter
        let state = crate::dpop::generate_nonce();

        // Build authorization parameters
        let mut params = HashMap::new();
        params.insert("response_type", "code".to_string());
        params.insert("client_id", self.client_metadata.client_id.clone());
        params.insert("code_challenge", pkce.challenge.clone());
        params.insert("code_challenge_method", pkce.method.to_string());
        params.insert("state", state.clone());

        if let Some(uri) = self.client_metadata.redirect_uris.first() {
            params.insert("redirect_uri", uri.clone());
        }

        if let Some(ref scope) = self.client_metadata.scope {
            params.insert("scope", scope.clone());
        }

        // Try PAR (Pushed Authorization Request) if supported
        let authorization_url =
            if let Some(ref par_endpoint) = server_metadata.pushed_authorization_request_endpoint {
                let par_response = self
                    .pushed_authorization_request(
                        par_endpoint,
                        &params,
                        &dpop_key,
                        &server_metadata.token_endpoint,
                    )
                    .await?;

                let mut url = Url::parse(&server_metadata.authorization_endpoint)?;
                url.query_pairs_mut()
                    .append_pair("request_uri", &par_response.request_uri)
                    .append_pair("client_id", &self.client_metadata.client_id);
                url
            } else {
                // Direct authorization URL with query parameters
                let mut url = Url::parse(&server_metadata.authorization_endpoint)?;
                for (key, value) in &params {
                    url.query_pairs_mut().append_pair(key, value);
                }
                url
            };

        let auth_state = AuthState {
            issuer: server_metadata.issuer.clone(),
            verifier: pkce.verifier,
            dpop_key: dpop_key.private_jwk.clone(),
            app_state: Some(state),
        };

        Ok((authorization_url, auth_state))
    }

    /// Send a Pushed Authorization Request (PAR).
    async fn pushed_authorization_request(
        &self,
        par_endpoint: &str,
        params: &HashMap<&str, String>,
        dpop_key: &DpopKey,
        _token_endpoint: &str,
    ) -> Result<ParResponse, OAuthError> {
        let dpop_proof = build_dpop_proof(dpop_key, "POST", par_endpoint, None, None)?;

        let resp = self
            .http
            .post(par_endpoint)
            .header("DPoP", &dpop_proof)
            .form(params)
            .send()
            .await?;

        // Check for DPoP nonce requirement
        if let Some(nonce) = resp.headers().get("dpop-nonce") {
            let nonce_str = nonce
                .to_str()
                .map_err(|e| OAuthError::Other(format!("Invalid DPoP-Nonce header: {e}")))?;
            if let Ok(origin) = Url::parse(par_endpoint).map(|u| u.origin().ascii_serialization()) {
                self.dpop_nonces.set(&origin, nonce_str);
            }

            // Retry with nonce
            let dpop_proof =
                build_dpop_proof(dpop_key, "POST", par_endpoint, Some(nonce_str), None)?;
            let resp = self
                .http
                .post(par_endpoint)
                .header("DPoP", &dpop_proof)
                .form(params)
                .send()
                .await?
                .error_for_status()
                .map_err(OAuthError::Http)?;
            let par: ParResponse = resp.json().await?;
            return Ok(par);
        }

        let resp = resp.error_for_status().map_err(OAuthError::Http)?;
        let par: ParResponse = resp.json().await?;
        Ok(par)
    }

    /// Handle the OAuth callback, exchanging the authorization code for tokens.
    ///
    /// Parameters:
    /// - `code`: The authorization code from the callback
    /// - `state`: The state from the auth state store
    /// - `auth_state`: The stored `AuthState` from the `authorize()` call
    /// - `server_metadata`: The authorization server metadata
    pub async fn callback(
        &self,
        code: &str,
        auth_state: &AuthState,
        server_metadata: &OAuthServerMetadata,
    ) -> Result<TokenSet, OAuthError> {
        // Reconstruct the DPoP key from stored state
        let dpop_key = dpop_key_from_jwk(&auth_state.dpop_key)?;

        // Exchange authorization code for tokens
        let token_response = self
            .exchange_code(
                &server_metadata.token_endpoint,
                code,
                &auth_state.verifier,
                &dpop_key,
            )
            .await?;

        // Verify issuer matches
        let actual_issuer = auth_state.issuer.trim_end_matches('/');
        let expected_issuer = server_metadata.issuer.trim_end_matches('/');
        if actual_issuer != expected_issuer {
            return Err(OAuthError::IssuerMismatch {
                expected: expected_issuer.to_string(),
                actual: actual_issuer.to_string(),
            });
        }

        let token_set = TokenSet::from_response(&server_metadata.issuer, &token_response);
        Ok(token_set)
    }

    /// Exchange an authorization code for tokens at the token endpoint.
    async fn exchange_code(
        &self,
        token_endpoint: &str,
        code: &str,
        verifier: &str,
        dpop_key: &DpopKey,
    ) -> Result<OAuthTokenResponse, OAuthError> {
        let redirect_uri = self
            .client_metadata
            .redirect_uris
            .first()
            .ok_or_else(|| OAuthError::MissingField("redirect_uris".into()))?;

        let nonce = Url::parse(token_endpoint)
            .ok()
            .map(|u| u.origin().ascii_serialization())
            .and_then(|origin| self.dpop_nonces.get(&origin));

        let dpop_proof =
            build_dpop_proof(dpop_key, "POST", token_endpoint, nonce.as_deref(), None)?;

        let mut form = HashMap::new();
        form.insert("grant_type", "authorization_code");
        form.insert("code", code);
        form.insert("code_verifier", verifier);
        form.insert("redirect_uri", redirect_uri.as_str());
        form.insert("client_id", &self.client_metadata.client_id);

        let resp = self
            .http
            .post(token_endpoint)
            .header("DPoP", &dpop_proof)
            .form(&form)
            .send()
            .await?;

        // Handle DPoP nonce rotation
        if let Some(nonce) = resp.headers().get("dpop-nonce") {
            let nonce_str = nonce
                .to_str()
                .map_err(|e| OAuthError::Other(format!("Invalid DPoP-Nonce header: {e}")))?;
            if let Ok(origin) = Url::parse(token_endpoint).map(|u| u.origin().ascii_serialization())
            {
                self.dpop_nonces.set(&origin, nonce_str);
            }

            // If the server returned an error requiring a nonce, retry
            if resp.status() == reqwest::StatusCode::BAD_REQUEST {
                let dpop_proof =
                    build_dpop_proof(dpop_key, "POST", token_endpoint, Some(nonce_str), None)?;
                let resp = self
                    .http
                    .post(token_endpoint)
                    .header("DPoP", &dpop_proof)
                    .form(&form)
                    .send()
                    .await?;
                return parse_token_response(resp).await;
            }
        }

        parse_token_response(resp).await
    }

    /// Refresh an access token using a refresh token.
    pub async fn refresh_token(
        &self,
        server_metadata: &OAuthServerMetadata,
        token_set: &TokenSet,
        dpop_key: &DpopKey,
    ) -> Result<TokenSet, OAuthError> {
        let refresh_token = token_set
            .refresh_token
            .as_deref()
            .ok_or(OAuthError::RefreshFailed("No refresh token".into()))?;

        let token_endpoint = &server_metadata.token_endpoint;
        let nonce = Url::parse(token_endpoint)
            .ok()
            .map(|u| u.origin().ascii_serialization())
            .and_then(|origin| self.dpop_nonces.get(&origin));

        let dpop_proof =
            build_dpop_proof(dpop_key, "POST", token_endpoint, nonce.as_deref(), None)?;

        let mut form = HashMap::new();
        form.insert("grant_type", "refresh_token");
        form.insert("refresh_token", refresh_token);
        form.insert("client_id", &self.client_metadata.client_id);

        let resp = self
            .http
            .post(token_endpoint)
            .header("DPoP", &dpop_proof)
            .form(&form)
            .send()
            .await?;

        // Handle DPoP nonce rotation
        if let Some(nonce_header) = resp.headers().get("dpop-nonce") {
            let nonce_str = nonce_header
                .to_str()
                .map_err(|e| OAuthError::Other(format!("Invalid DPoP-Nonce header: {e}")))?;
            if let Ok(origin) = Url::parse(token_endpoint).map(|u| u.origin().ascii_serialization())
            {
                self.dpop_nonces.set(&origin, nonce_str);
            }

            if resp.status() == reqwest::StatusCode::BAD_REQUEST {
                let dpop_proof =
                    build_dpop_proof(dpop_key, "POST", token_endpoint, Some(nonce_str), None)?;
                let resp = self
                    .http
                    .post(token_endpoint)
                    .header("DPoP", &dpop_proof)
                    .form(&form)
                    .send()
                    .await?;
                let token_response = parse_token_response(resp).await?;
                return Ok(TokenSet::from_response(
                    &server_metadata.issuer,
                    &token_response,
                ));
            }
        }

        let token_response = parse_token_response(resp).await?;
        Ok(TokenSet::from_response(
            &server_metadata.issuer,
            &token_response,
        ))
    }

    /// Revoke a token (access or refresh) at the revocation endpoint.
    pub async fn revoke_token(
        &self,
        server_metadata: &OAuthServerMetadata,
        token: &str,
    ) -> Result<(), OAuthError> {
        let revocation_endpoint = server_metadata
            .revocation_endpoint
            .as_deref()
            .ok_or_else(|| OAuthError::MissingField("revocation_endpoint".into()))?;

        let mut form = HashMap::new();
        form.insert("token", token);
        form.insert("client_id", self.client_metadata.client_id.as_str());

        self.http
            .post(revocation_endpoint)
            .form(&form)
            .send()
            .await?
            .error_for_status()
            .map_err(OAuthError::Http)?;

        Ok(())
    }

    /// Get a reference to the DPoP nonce cache.
    pub fn dpop_nonces(&self) -> &DpopNonceCache {
        &self.dpop_nonces
    }
}

/// Reconstruct a DpopKey from a stored private JWK.
pub fn dpop_key_from_jwk(jwk: &serde_json::Value) -> Result<DpopKey, OAuthError> {
    let public_jwk = {
        let mut pub_jwk = jwk.clone();
        if let Some(obj) = pub_jwk.as_object_mut() {
            obj.remove("d");
        }
        pub_jwk
    };

    Ok(DpopKey {
        private_jwk: jwk.clone(),
        public_jwk,
    })
}

/// Parse a token response, handling OAuth error responses.
async fn parse_token_response(resp: reqwest::Response) -> Result<OAuthTokenResponse, OAuthError> {
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "unknown error".to_string());

        // Try to parse as OAuth error
        if let Ok(error_obj) = serde_json::from_str::<serde_json::Value>(&body) {
            let error = error_obj
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let description = error_obj
                .get("error_description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            return Err(OAuthError::ServerError {
                error,
                error_description: description,
            });
        }

        return Err(OAuthError::Other(format!(
            "Token request failed ({status}): {body}"
        )));
    }

    let token_response: OAuthTokenResponse = resp.json().await?;
    Ok(token_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client_metadata() -> OAuthClientMetadata {
        OAuthClientMetadata {
            client_id: "https://myapp.example.com/client-metadata.json".into(),
            redirect_uris: vec!["https://myapp.example.com/callback".into()],
            response_types: Some(vec!["code".into()]),
            grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
            scope: Some("atproto transition:generic".into()),
            token_endpoint_auth_method: Some("none".into()),
            token_endpoint_auth_signing_alg: None,
            application_type: Some("web".into()),
            dpop_bound_access_tokens: Some(true),
            client_name: Some("Test App".into()),
            client_uri: None,
            logo_uri: None,
        }
    }

    #[test]
    fn create_oauth_client() {
        let client = OAuthClient::new(test_client_metadata());
        assert_eq!(
            client.client_metadata.client_id,
            "https://myapp.example.com/client-metadata.json"
        );
    }

    #[test]
    fn dpop_nonce_cache() {
        let cache = DpopNonceCache::new();
        assert!(cache.get("https://bsky.social").is_none());

        cache.set("https://bsky.social", "nonce-123");
        assert_eq!(
            cache.get("https://bsky.social"),
            Some("nonce-123".to_string())
        );

        cache.set("https://bsky.social", "nonce-456");
        assert_eq!(
            cache.get("https://bsky.social"),
            Some("nonce-456".to_string())
        );
    }

    #[test]
    fn dpop_key_from_jwk_roundtrip() {
        let key = DpopKey::generate().unwrap();
        let reconstructed = dpop_key_from_jwk(&key.private_jwk).unwrap();

        assert!(reconstructed.private_jwk.get("d").is_some());
        assert!(reconstructed.public_jwk.get("d").is_none());
        assert_eq!(reconstructed.public_jwk["kty"], "EC");
        assert_eq!(reconstructed.public_jwk["crv"], "P-256");
    }

    #[test]
    fn parse_oauth_error_response() {
        let error_json = r#"{"error":"invalid_grant","error_description":"Token expired"}"#;
        let obj: serde_json::Value = serde_json::from_str(error_json).unwrap();
        let error = obj["error"].as_str().unwrap();
        let desc = obj["error_description"].as_str().unwrap();
        assert_eq!(error, "invalid_grant");
        assert_eq!(desc, "Token expired");
    }

    #[test]
    fn auth_state_serde_roundtrip() {
        let key = DpopKey::generate().unwrap();
        let state = AuthState {
            issuer: "https://bsky.social".into(),
            verifier: "test-verifier".into(),
            dpop_key: key.private_jwk.clone(),
            app_state: Some("state-123".into()),
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: AuthState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.issuer, "https://bsky.social");
        assert_eq!(parsed.verifier, "test-verifier");
        assert!(parsed.dpop_key.get("d").is_some());
    }
}
