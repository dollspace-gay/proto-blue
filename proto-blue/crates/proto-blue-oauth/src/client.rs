//! OAuth 2.0 client for AT Protocol.
//!
//! Implements the full OAuth authorization code flow with PKCE, `DPoP`, and PAR.
//!
//! HTTP transport is abstracted behind
//! [`proto_blue_common::fetch::FetchHandler`] so the same flow drives
//! `reqwest` on native and browser `fetch()` on `wasm32-unknown-unknown`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use proto_blue_common::fetch::{FetchHandler, HttpRequest, HttpResponse};
use url::Url;

use crate::dpop::{DpopKey, build_dpop_proof};
use crate::error::OAuthError;
use crate::pkce::generate_pkce;
use crate::types::{
    AuthState, OAuthClientMetadata, OAuthServerMetadata, OAuthTokenResponse, ParResponse, TokenSet,
};

/// Per-origin `DPoP` nonce cache.
#[derive(Debug, Clone, Default)]
pub struct DpopNonceCache {
    nonces: Arc<Mutex<HashMap<String, String>>>,
}

impl DpopNonceCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the cached nonce for an origin.
    #[must_use]
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
/// 2. Build authorization URL (with PKCE + `DPoP`, optional PAR)
/// 3. Exchange authorization code for tokens
/// 4. Refresh tokens when they expire
/// 5. Revoke tokens on sign-out
pub struct OAuthClient {
    /// Client metadata (`client_id`, `redirect_uris`, etc.).
    pub client_metadata: OAuthClientMetadata,
    /// HTTP transport.
    fetcher: Arc<dyn FetchHandler>,
    /// `DPoP` nonce cache (per-origin).
    dpop_nonces: DpopNonceCache,
    /// Optional signing keyset for `private_key_jwt` client auth. When
    /// set, token-endpoint requests include a signed `client_assertion`
    /// alongside the grant.
    keyset: Option<Arc<crate::jwt_assertion::ClientKeyset>>,
}

impl OAuthClient {
    /// Create a new OAuth client using the crate's default fetch handler.
    ///
    /// With the `fetch-reqwest` feature (default on native), a fresh
    /// `reqwest::Client` is constructed internally. Otherwise the caller
    /// must use [`Self::with_fetch_handler`].
    #[cfg(feature = "fetch-reqwest")]
    #[must_use]
    pub fn new(client_metadata: OAuthClientMetadata) -> Self {
        Self::with_fetch_handler(
            client_metadata,
            Arc::new(proto_blue_common::fetch::ReqwestFetcher::new()),
        )
    }

    /// Create a new OAuth client with a user-supplied `reqwest::Client`.
    ///
    /// Back-compat constructor — wraps the client in a
    /// [`proto_blue_common::fetch::ReqwestFetcher`].
    #[cfg(feature = "fetch-reqwest")]
    #[must_use]
    pub fn with_http_client(client_metadata: OAuthClientMetadata, http: reqwest::Client) -> Self {
        Self::with_fetch_handler(
            client_metadata,
            Arc::new(proto_blue_common::fetch::ReqwestFetcher::from_client(http)),
        )
    }

    /// Create a new OAuth client with an arbitrary [`FetchHandler`].
    ///
    /// Primary entry point for wasm and for unit tests that want to mock
    /// out the authorization server.
    pub fn with_fetch_handler(
        client_metadata: OAuthClientMetadata,
        fetcher: Arc<dyn FetchHandler>,
    ) -> Self {
        Self {
            client_metadata,
            fetcher,
            dpop_nonces: DpopNonceCache::new(),
            keyset: None,
        }
    }

    /// Install a `private_key_jwt` signing keyset. After this call,
    /// all token-endpoint requests emitted by `exchange_code` and
    /// `refresh_token` include a signed `client_assertion` alongside
    /// the grant (RFC 7523 §2.2).
    ///
    /// The keyset is ignored when the authorization server doesn't
    /// advertise a compatible `token_endpoint_auth_signing_alg_values_supported`
    /// — in that case the client silently falls back to public-client
    /// (DPoP-only) auth, matching the TS SDK's behaviour.
    #[must_use]
    pub fn with_keyset(mut self, keyset: crate::jwt_assertion::ClientKeyset) -> Self {
        self.keyset = Some(Arc::new(keyset));
        self
    }

    /// Convenience constructor for loopback clients (CLIs, desktop
    /// apps). Parses a `http://localhost[/?scope=…&redirect_uri=…]`
    /// client ID into implicit [`OAuthClientMetadata`] via
    /// [`crate::loopback::loopback_client_metadata`] and configures a
    /// native-reqwest fetch handler.
    #[cfg(feature = "fetch-reqwest")]
    pub fn new_loopback(client_id: &str) -> Result<Self, OAuthError> {
        let metadata = crate::loopback::loopback_client_metadata(client_id)?;
        Ok(Self::new(metadata))
    }

    /// Internal: build the client-auth form fields for a token-endpoint
    /// request. Returns `[(client_assertion_type, ...), (client_assertion, ...)]`
    /// when `private_key_jwt` is configured and the AS advertises a
    /// matching `alg`; otherwise returns an empty vec (public client).
    fn client_auth_fields(
        &self,
        server_metadata: &OAuthServerMetadata,
    ) -> Result<Vec<(String, String)>, OAuthError> {
        let Some(keyset) = &self.keyset else {
            return Ok(Vec::new());
        };
        let algs = server_metadata
            .token_endpoint_auth_signing_alg_values_supported
            .as_ref();
        let Some(algs) = algs else {
            return Ok(Vec::new());
        };
        let Some(key) = keyset.select_for(algs) else {
            return Ok(Vec::new());
        };
        let assertion = crate::jwt_assertion::build_client_assertion(
            key,
            &self.client_metadata.client_id,
            &server_metadata.token_endpoint,
        )?;
        Ok(vec![
            (
                "client_assertion_type".to_string(),
                crate::jwt_assertion::CLIENT_ASSERTION_TYPE.to_string(),
            ),
            ("client_assertion".to_string(), assertion),
        ])
    }

    /// Fetch a client metadata document from the client's `client_id` URL.
    ///
    /// In atproto's OAuth profile, `client_id` is a URL that serves a
    /// JSON document describing the client (per the atproto client-id-
    /// metadata-document spec, which extends RFC 7591). Use this when
    /// you want to load client metadata dynamically instead of hard-
    /// coding it — e.g. an authorization server fetching a third-party
    /// client's metadata before deciding whether to trust it.
    ///
    /// Strict checks:
    /// - response must be HTTP success,
    /// - `Content-Type` must be `application/json` (atproto requires
    ///   this exactly — the spec bans other content types),
    /// - parsed document's `client_id` must equal the URL it was
    ///   fetched from, exactly.
    pub async fn fetch_client_metadata(
        &self,
        client_id_url: &str,
    ) -> Result<OAuthClientMetadata, OAuthError> {
        let req = HttpRequest::get(client_id_url).with_header("accept", "application/json");
        let resp = self.fetcher.fetch(req).await?;

        if !resp.is_success() {
            return Err(OAuthError::Other(format!(
                "client metadata fetch failed: HTTP {}",
                resp.status
            )));
        }

        // Strict Content-Type check. atproto's profile requires
        // `application/json`; accepting other types could open up
        // protocol-confusion attacks if an attacker controls the URL.
        let ct = resp.header("content-type").unwrap_or("").to_string();
        // Allow parameters like `application/json; charset=utf-8`.
        let base_ct = ct
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if base_ct != "application/json" {
            return Err(OAuthError::Other(format!(
                "client metadata must be application/json, got {ct:?}"
            )));
        }

        let metadata: OAuthClientMetadata = serde_json::from_slice(&resp.body)?;

        // The document's `client_id` must match the URL it came from,
        // otherwise an authorization server couldn't trust that the
        // document really describes this client.
        if metadata.client_id != client_id_url {
            return Err(OAuthError::Other(format!(
                "client metadata `client_id` mismatch: document says {:?}, fetched from {:?}",
                metadata.client_id, client_id_url
            )));
        }

        Ok(metadata)
    }

    /// Discover protected-resource metadata (RFC 9728) for a
    /// resource URL (typically a PDS base URL like
    /// `https://pds.example`).
    ///
    /// Fetches `{resource}/.well-known/oauth-protected-resource` and
    /// enforces:
    /// - HTTP success status
    /// - JSON content-type
    /// - the returned `resource` field matches the URL we fetched from
    /// - `authorization_servers` has exactly one entry (atproto profile
    ///   requirement)
    ///
    /// Returns the metadata on success; on validation failure
    /// [`OAuthError::Other`] carries a description of which check failed.
    pub async fn discover_resource(
        &self,
        resource_url: &str,
    ) -> Result<crate::types::OAuthProtectedResourceMetadata, OAuthError> {
        let url = format!(
            "{}/.well-known/oauth-protected-resource",
            resource_url.trim_end_matches('/')
        );
        let resp = self
            .fetcher
            .fetch(
                proto_blue_common::fetch::HttpRequest::get(&url)
                    .with_header("accept", "application/json"),
            )
            .await?;
        if !resp.is_success() {
            return Err(OAuthError::Other(format!(
                "protected-resource discovery failed: HTTP {}",
                resp.status,
            )));
        }
        // Content-type validation — atproto requires strict JSON.
        let ct = resp
            .header("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if !ct
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq("application/json")
        {
            return Err(OAuthError::Other(format!(
                "protected-resource metadata must be application/json, got {ct:?}",
            )));
        }
        let metadata: crate::types::OAuthProtectedResourceMetadata =
            serde_json::from_slice(&resp.body)?;

        // `resource` self-reference check — protects against an
        // attacker hosting a metadata doc that lies about which
        // resource it describes.
        let expected = resource_url.trim_end_matches('/');
        let actual = metadata.resource.trim_end_matches('/');
        if expected != actual {
            return Err(OAuthError::Other(format!(
                "protected-resource metadata `resource` mismatch: \
                 document says {actual:?}, fetched from {expected:?}",
            )));
        }

        // atproto profile: exactly one authorization_servers entry.
        match metadata.authorization_servers.as_deref() {
            Some([_]) => {}
            Some(list) => {
                return Err(OAuthError::Other(format!(
                    "protected-resource metadata must list exactly one \
                     authorization_server; got {}",
                    list.len(),
                )));
            }
            None => {
                return Err(OAuthError::Other(
                    "protected-resource metadata missing `authorization_servers`".into(),
                ));
            }
        }

        Ok(metadata)
    }

    /// Discover authorization server metadata from an issuer URL.
    ///
    /// Fetches `{issuer}/.well-known/oauth-authorization-server` per RFC 8414.
    pub async fn discover_server(&self, issuer: &str) -> Result<OAuthServerMetadata, OAuthError> {
        let url = format!(
            "{}/.well-known/oauth-authorization-server",
            issuer.trim_end_matches('/')
        );
        let resp = self.fetcher.fetch(HttpRequest::get(url)).await?;
        if !resp.is_success() {
            return Err(OAuthError::Other(format!(
                "authorization server discovery failed: HTTP {}",
                resp.status
            )));
        }
        let metadata: OAuthServerMetadata = serde_json::from_slice(&resp.body)?;

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
        let body = encode_form(params.iter().map(|(k, v)| (*k, v.as_str())));
        let dpop_proof = build_dpop_proof(dpop_key, "POST", par_endpoint, None, None)?;

        let resp = self
            .post_form(par_endpoint, &body, Some(&dpop_proof))
            .await?;

        // Check for DPoP nonce requirement
        if let Some(nonce_str) = resp
            .header("dpop-nonce")
            .map(std::string::ToString::to_string)
        {
            if let Ok(origin) = Url::parse(par_endpoint).map(|u| u.origin().ascii_serialization()) {
                self.dpop_nonces.set(&origin, &nonce_str);
            }

            // Retry with nonce
            let dpop_proof =
                build_dpop_proof(dpop_key, "POST", par_endpoint, Some(&nonce_str), None)?;
            let resp = self
                .post_form(par_endpoint, &body, Some(&dpop_proof))
                .await?;
            if !resp.is_success() {
                return Err(OAuthError::Other(format!(
                    "PAR failed: HTTP {}: {}",
                    resp.status,
                    String::from_utf8_lossy(&resp.body)
                )));
            }
            let par: ParResponse = serde_json::from_slice(&resp.body)?;
            return Ok(par);
        }

        if !resp.is_success() {
            return Err(OAuthError::Other(format!(
                "PAR failed: HTTP {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            )));
        }
        let par: ParResponse = serde_json::from_slice(&resp.body)?;
        Ok(par)
    }

    /// Handle the OAuth callback **with server-supplied `iss`
    /// verification** (RFC 9207).
    ///
    /// When the AS advertises
    /// `authorization_response_iss_parameter_supported: true`, the
    /// callback URL carries `?iss=<issuer>`. This variant asserts
    /// that the received `iss` equals the one we stored in
    /// `auth_state` before accepting the code. Mitigates the "AS
    /// confusion" attack class: an attacker who tricks the user into
    /// returning to a callback issued by the wrong AS would otherwise
    /// silently cause token exchange at the expected AS with a code
    /// the attacker knows.
    ///
    /// Callers that haven't wired through the query `iss` can still
    /// use [`Self::callback`], which skips this check.
    pub async fn callback_with_iss(
        &self,
        code: &str,
        iss: Option<&str>,
        auth_state: &AuthState,
        server_metadata: &OAuthServerMetadata,
    ) -> Result<TokenSet, OAuthError> {
        if server_metadata
            .authorization_response_iss_parameter_supported
            .unwrap_or(false)
        {
            let provided = iss.ok_or_else(|| {
                OAuthError::Other(
                    "authorization response is missing required `iss` parameter".into(),
                )
            })?;
            let expected = server_metadata.issuer.trim_end_matches('/');
            let actual = provided.trim_end_matches('/');
            if expected != actual {
                return Err(OAuthError::IssuerMismatch {
                    expected: expected.to_string(),
                    actual: actual.to_string(),
                });
            }
        }
        self.callback(code, auth_state, server_metadata).await
    }

    /// Variant of [`Self::callback_with_iss`] that records the
    /// resource-server (PDS) URL onto the returned [`TokenSet`] as
    /// `aud`. Pass the PDS URL discovered during identity resolution;
    /// `DPoP` proofs on subsequent resource-server requests bind `htu`
    /// to that audience so a stolen token can't be replayed elsewhere.
    pub async fn callback_with_iss_and_aud(
        &self,
        code: &str,
        iss: Option<&str>,
        aud: Option<&str>,
        auth_state: &AuthState,
        server_metadata: &OAuthServerMetadata,
    ) -> Result<TokenSet, OAuthError> {
        let mut ts = self
            .callback_with_iss(code, iss, auth_state, server_metadata)
            .await?;
        if let Some(url) = aud {
            ts.aud = Some(url.to_string());
        }
        Ok(ts)
    }

    /// Variant of [`Self::callback_with_iss_and_aud`] that verifies
    /// the token response's `sub` against a DID the client resolved
    /// up-front (e.g. from [`crate::resolve::resolve_input`]'s output).
    ///
    /// Returns `Err` if the AS handed back a token for a different
    /// user — catches a compromised AS trying to swap identities.
    /// When `expected_did` is `None`, behaves identically to
    /// [`Self::callback_with_iss_and_aud`].
    pub async fn callback_verified(
        &self,
        code: &str,
        iss: Option<&str>,
        aud: Option<&str>,
        expected_did: Option<&str>,
        auth_state: &AuthState,
        server_metadata: &OAuthServerMetadata,
    ) -> Result<TokenSet, OAuthError> {
        let ts = self
            .callback_with_iss_and_aud(code, iss, aud, auth_state, server_metadata)
            .await?;
        crate::resolve::verify_token_sub(expected_did, &ts.sub)?;
        Ok(ts)
    }

    /// Handle the OAuth callback, exchanging the authorization code for tokens.
    ///
    /// Parameters:
    /// - `code`: The authorization code from the callback
    /// - `state`: The state from the auth state store
    /// - `auth_state`: The stored `AuthState` from the `authorize()` call
    /// - `server_metadata`: The authorization server metadata
    ///
    /// Does **not** verify the `iss` query parameter; use
    /// [`Self::callback_with_iss`] when the AS advertises
    /// `authorization_response_iss_parameter_supported`.
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
            .exchange_code(server_metadata, code, &auth_state.verifier, &dpop_key)
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

        let token_set = TokenSet::from_response(&server_metadata.issuer, None, &token_response);
        Ok(token_set)
    }

    /// Exchange an authorization code for tokens at the token endpoint.
    async fn exchange_code(
        &self,
        server_metadata: &OAuthServerMetadata,
        code: &str,
        verifier: &str,
        dpop_key: &DpopKey,
    ) -> Result<OAuthTokenResponse, OAuthError> {
        let token_endpoint = server_metadata.token_endpoint.as_str();
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

        let auth_fields = self.client_auth_fields(server_metadata)?;
        let mut fields: Vec<(String, String)> = vec![
            ("grant_type".into(), "authorization_code".into()),
            ("code".into(), code.into()),
            ("code_verifier".into(), verifier.into()),
            ("redirect_uri".into(), redirect_uri.clone()),
            ("client_id".into(), self.client_metadata.client_id.clone()),
        ];
        fields.extend(auth_fields);
        let body = encode_form(fields.iter().map(|(k, v)| (k.as_str(), v.as_str())));

        let resp = self
            .post_form(token_endpoint, &body, Some(&dpop_proof))
            .await?;

        // Handle DPoP nonce rotation. Two things must both be true to
        // retry:
        //   1. Server sent a `DPoP-Nonce` header telling us which
        //      nonce to use next time.
        //   2. Server explicitly told us the last request was rejected
        //      *because* of the missing/stale nonce (RFC 9449 §8.2).
        //      We inspect the JSON body for `error == "use_dpop_nonce"`.
        //      Previously the code retried on any 400 with a nonce
        //      header, which looks similar but misidentifies genuine
        //      400s (bad form data) as nonce-retry candidates and
        //      silently double-fires the request.
        if let Some(nonce_str) = resp
            .header("dpop-nonce")
            .map(std::string::ToString::to_string)
        {
            if let Ok(origin) = Url::parse(token_endpoint).map(|u| u.origin().ascii_serialization())
            {
                self.dpop_nonces.set(&origin, &nonce_str);
            }

            if is_use_dpop_nonce_error(&resp) {
                let dpop_proof =
                    build_dpop_proof(dpop_key, "POST", token_endpoint, Some(&nonce_str), None)?;
                let resp = self
                    .post_form(token_endpoint, &body, Some(&dpop_proof))
                    .await?;
                return parse_token_response(resp);
            }
        }

        parse_token_response(resp)
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

        let auth_fields = self.client_auth_fields(server_metadata)?;
        let mut fields: Vec<(String, String)> = vec![
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), refresh_token.into()),
            ("client_id".into(), self.client_metadata.client_id.clone()),
        ];
        fields.extend(auth_fields);
        let body = encode_form(fields.iter().map(|(k, v)| (k.as_str(), v.as_str())));

        let resp = self
            .post_form(token_endpoint, &body, Some(&dpop_proof))
            .await?;

        // Handle DPoP nonce rotation. Same discriminator logic as
        // `exchange_code` — see the comment there for why we inspect
        // the body instead of treating every 400 as a nonce retry.
        if let Some(nonce_str) = resp
            .header("dpop-nonce")
            .map(std::string::ToString::to_string)
        {
            if let Ok(origin) = Url::parse(token_endpoint).map(|u| u.origin().ascii_serialization())
            {
                self.dpop_nonces.set(&origin, &nonce_str);
            }

            if is_use_dpop_nonce_error(&resp) {
                let dpop_proof =
                    build_dpop_proof(dpop_key, "POST", token_endpoint, Some(&nonce_str), None)?;
                let resp = self
                    .post_form(token_endpoint, &body, Some(&dpop_proof))
                    .await?;
                let token_response = parse_token_response(resp)?;
                let mut new_ts = TokenSet::from_response(
                    &server_metadata.issuer,
                    token_set.aud.as_deref(),
                    &token_response,
                );
                // Preserve the refresh token on rotation-less
                // responses (RFC 6749 §6 allows omitting it).
                if new_ts.refresh_token.is_none() {
                    new_ts.refresh_token = token_set.refresh_token.clone();
                }
                return Ok(new_ts);
            }
        }

        let token_response = parse_token_response(resp)?;
        let mut new_ts = TokenSet::from_response(
            &server_metadata.issuer,
            token_set.aud.as_deref(),
            &token_response,
        );
        if new_ts.refresh_token.is_none() {
            new_ts.refresh_token = token_set.refresh_token.clone();
        }
        Ok(new_ts)
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

        let form: [(&str, &str); 2] = [
            ("token", token),
            ("client_id", self.client_metadata.client_id.as_str()),
        ];
        let body = encode_form(form.iter().copied());

        let resp = self.post_form(revocation_endpoint, &body, None).await?;
        if !resp.is_success() {
            return Err(OAuthError::Other(format!(
                "revocation failed: HTTP {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            )));
        }

        Ok(())
    }

    /// Get a reference to the `DPoP` nonce cache.
    #[must_use]
    pub const fn dpop_nonces(&self) -> &DpopNonceCache {
        &self.dpop_nonces
    }

    /// POST an `application/x-www-form-urlencoded` body. Optional `DPoP`
    /// proof header is threaded through — the call sites that need it
    /// pass `Some(&proof)`, the revocation endpoint passes `None`.
    async fn post_form(
        &self,
        url: &str,
        body: &str,
        dpop_proof: Option<&str>,
    ) -> Result<HttpResponse, OAuthError> {
        let mut req = HttpRequest::post(url)
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(body.as_bytes().to_vec());
        if let Some(proof) = dpop_proof {
            req = req.with_header("dpop", proof);
        }
        self.fetcher.fetch(req).await.map_err(OAuthError::Fetch)
    }
}

/// Encode a sequence of `(name, value)` pairs as an
/// `application/x-www-form-urlencoded` string.
fn encode_form<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish()
}

/// Reconstruct a `DpopKey` from a stored private JWK.
///
/// Infers the algorithm from the JWK's `crv` field: `P-256` → ES256,
/// `secp256k1` → ES256K (RFC 8812). Anything else is rejected — we
/// don't want to silently downgrade a key the caller thought was
/// stored for a specific curve.
pub fn dpop_key_from_jwk(jwk: &serde_json::Value) -> Result<DpopKey, OAuthError> {
    let crv = jwk
        .get("crv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::Other("JWK missing 'crv' field".into()))?;
    let alg = match crv {
        "P-256" => crate::dpop::DpopAlg::Es256,
        "secp256k1" => crate::dpop::DpopAlg::Es256k,
        other => {
            return Err(OAuthError::Other(format!(
                "unsupported JWK curve for DPoP: {other}"
            )));
        }
    };

    let public_jwk = {
        let mut pub_jwk = jwk.clone();
        if let Some(obj) = pub_jwk.as_object_mut() {
            obj.remove("d");
        }
        pub_jwk
    };

    Ok(DpopKey {
        alg,
        private_jwk: jwk.clone(),
        public_jwk,
    })
}

/// Validate an [`OAuthClientMetadata`] document against the atproto
/// OAuth client-metadata profile. Returns `Ok(())` on success;
/// `Err(OAuthError::Other)` on any policy violation.
///
/// Checks (subset of TS `validate-client-metadata.ts`):
///
/// - `redirect_uris` is non-empty.
/// - `response_types` contains `"code"` (when present).
/// - `grant_types` contains `"authorization_code"` (when present).
/// - `scope` is either absent or includes the atproto-required
///   `"atproto"` token (otherwise the AS will reject it).
/// - `token_endpoint_auth_method`, if present, is a recognised value
///   (`"none"`, `"private_key_jwt"`, `"client_secret_basic"`,
///   `"client_secret_post"`).
/// - `application_type`, if present, is `"web"` or `"native"`.
///
/// The full TS validator also cross-checks auth-method ↔
/// signing-alg ↔ JWKS presence; that layer lives above the client
/// metadata itself and is out of scope here.
pub fn validate_client_metadata(meta: &OAuthClientMetadata) -> Result<(), OAuthError> {
    if meta.redirect_uris.is_empty() {
        return Err(OAuthError::Other(
            "client metadata must declare at least one redirect_uri".into(),
        ));
    }

    if let Some(response_types) = &meta.response_types
        && !response_types.iter().any(|r| r == "code")
    {
        return Err(OAuthError::Other(
            "client metadata `response_types` must include \"code\"".into(),
        ));
    }

    if let Some(grant_types) = &meta.grant_types
        && !grant_types.iter().any(|g| g == "authorization_code")
    {
        return Err(OAuthError::Other(
            "client metadata `grant_types` must include \"authorization_code\"".into(),
        ));
    }

    if let Some(scope) = &meta.scope
        && !scope.split_whitespace().any(|s| s == "atproto")
    {
        return Err(OAuthError::Other(
            "client metadata `scope` must include the \"atproto\" token".into(),
        ));
    }

    if let Some(m) = &meta.token_endpoint_auth_method {
        const VALID_METHODS: &[&str] = &[
            "none",
            "private_key_jwt",
            "client_secret_basic",
            "client_secret_post",
        ];
        if !VALID_METHODS.contains(&m.as_str()) {
            return Err(OAuthError::Other(format!(
                "unknown token_endpoint_auth_method: {m:?}",
            )));
        }
    }

    if let Some(app_type) = &meta.application_type
        && !matches!(app_type.as_str(), "web" | "native")
    {
        return Err(OAuthError::Other(format!(
            "application_type must be \"web\" or \"native\", got {app_type:?}",
        )));
    }

    Ok(())
}

/// `true` if a 4xx response signals that the client must retry with
/// the server-supplied `DPoP` nonce.
///
/// RFC 9449 §8.2: the authorization server returns
/// `{"error":"use_dpop_nonce"}` (400 at AS token/PAR endpoints, 401
/// at resource servers via `WWW-Authenticate: DPoP error="use_dpop_nonce"`).
/// This function checks both forms so a single caller can use it
/// regardless of where the response came from.
fn is_use_dpop_nonce_error(resp: &HttpResponse) -> bool {
    // AS form — JSON body on a 400.
    if resp.status == 400
        && let Ok(body) = std::str::from_utf8(&resp.body)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(body)
        && v.get("error").and_then(|e| e.as_str()) == Some("use_dpop_nonce")
    {
        return true;
    }
    // RS form — 401 with WWW-Authenticate carrying `error="use_dpop_nonce"`.
    if resp.status == 401
        && let Some(auth) = resp.header("www-authenticate")
        && auth.contains("error=\"use_dpop_nonce\"")
    {
        return true;
    }
    false
}

/// Parse a token response, handling OAuth error responses.
fn parse_token_response(resp: HttpResponse) -> Result<OAuthTokenResponse, OAuthError> {
    if !resp.is_success() {
        let status = resp.status;
        let body = String::from_utf8_lossy(&resp.body).to_string();

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

    let token_response: OAuthTokenResponse = serde_json::from_slice(&resp.body)?;
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

    #[cfg(feature = "fetch-reqwest")]
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
            dpop_key: key.private_jwk,
            app_state: Some("state-123".into()),
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: AuthState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.issuer, "https://bsky.social");
        assert_eq!(parsed.verifier, "test-verifier");
        assert!(parsed.dpop_key.get("d").is_some());
    }

    #[test]
    fn encode_form_produces_urlencoded_output() {
        let form = [("grant_type", "authorization_code"), ("code", "abc=xyz&")];
        let encoded = encode_form(form.iter().copied());
        assert_eq!(encoded, "grant_type=authorization_code&code=abc%3Dxyz%26");
    }

    // ── is_use_dpop_nonce_error ─────────────────────────────────────

    use proto_blue_common::fetch::{HttpHeaders, HttpResponse};

    fn response(status: u16, body: &[u8], headers: &[(&str, &str)]) -> HttpResponse {
        let mut h = HttpHeaders::new();
        for (k, v) in headers {
            h.insert(k.to_lowercase(), v.to_string());
        }
        HttpResponse {
            status,
            headers: h,
            body: body.to_vec(),
        }
    }

    #[test]
    fn use_dpop_nonce_detects_as_400_json_body() {
        let r = response(400, br#"{"error":"use_dpop_nonce"}"#, &[]);
        assert!(is_use_dpop_nonce_error(&r));
    }

    #[test]
    fn use_dpop_nonce_detects_rs_401_www_authenticate() {
        let r = response(
            401,
            b"",
            &[("www-authenticate", "DPoP error=\"use_dpop_nonce\"")],
        );
        assert!(is_use_dpop_nonce_error(&r));
    }

    #[test]
    fn use_dpop_nonce_ignores_unrelated_400() {
        // 400 with dpop-nonce header but NO use_dpop_nonce body —
        // this used to false-positive under the old "any 400" logic.
        let r = response(
            400,
            br#"{"error":"invalid_grant"}"#,
            &[("dpop-nonce", "nonce-xyz")],
        );
        assert!(!is_use_dpop_nonce_error(&r));
    }

    #[test]
    fn use_dpop_nonce_ignores_401_without_directive() {
        let r = response(401, b"", &[("www-authenticate", "Bearer realm=\"x\"")]);
        assert!(!is_use_dpop_nonce_error(&r));
    }

    #[test]
    fn use_dpop_nonce_ignores_success_status() {
        let r = response(200, br#"{"error":"use_dpop_nonce"}"#, &[]);
        assert!(!is_use_dpop_nonce_error(&r));
    }

    // ── validate_client_metadata ────────────────────────────────────

    fn valid_metadata() -> OAuthClientMetadata {
        OAuthClientMetadata {
            client_id: "https://example.com/client-metadata.json".into(),
            redirect_uris: vec!["https://example.com/cb".into()],
            response_types: Some(vec!["code".into()]),
            grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
            scope: Some("atproto transition:generic".into()),
            token_endpoint_auth_method: Some("none".into()),
            token_endpoint_auth_signing_alg: None,
            application_type: Some("web".into()),
            dpop_bound_access_tokens: Some(true),
            client_name: None,
            client_uri: None,
            logo_uri: None,
        }
    }

    #[test]
    fn metadata_valid_accepts() {
        assert!(validate_client_metadata(&valid_metadata()).is_ok());
    }

    #[test]
    fn metadata_rejects_empty_redirect_uris() {
        let mut m = valid_metadata();
        m.redirect_uris.clear();
        assert!(validate_client_metadata(&m).is_err());
    }

    #[test]
    fn metadata_rejects_scope_missing_atproto() {
        let mut m = valid_metadata();
        m.scope = Some("transition:generic".into());
        let err = validate_client_metadata(&m).unwrap_err().to_string();
        assert!(err.contains("\"atproto\""));
    }

    #[test]
    fn metadata_rejects_response_types_without_code() {
        let mut m = valid_metadata();
        m.response_types = Some(vec!["token".into()]);
        assert!(validate_client_metadata(&m).is_err());
    }

    #[test]
    fn metadata_rejects_unknown_application_type() {
        let mut m = valid_metadata();
        m.application_type = Some("desktop".into());
        assert!(validate_client_metadata(&m).is_err());
    }

    #[test]
    fn metadata_rejects_unknown_auth_method() {
        let mut m = valid_metadata();
        m.token_endpoint_auth_method = Some("weird".into());
        assert!(validate_client_metadata(&m).is_err());
    }
}
