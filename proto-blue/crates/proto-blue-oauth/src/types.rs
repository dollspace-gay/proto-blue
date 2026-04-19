//! OAuth 2.0 type definitions for AT Protocol.

use serde::{Deserialize, Serialize};

/// OAuth Protected Resource Metadata (RFC 9728).
///
/// A resource server publishes this at
/// `<resource>/.well-known/oauth-protected-resource` so clients can
/// learn which authorization servers are trusted to issue tokens for
/// it. atproto PDSes serve this document to enable
/// identity-to-authorization-server resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OAuthProtectedResourceMetadata {
    /// The resource's canonical URL. MUST equal the URL it was
    /// fetched from.
    pub resource: String,
    /// Authorization servers that this resource trusts. Per the
    /// atproto profile, exactly one entry — the PDS's chosen AS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<String>>,
    /// Supported bearer-token methods ("header", "body", "query"). At
    /// protocol level only "header" is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_methods_supported: Option<Vec<String>>,
    /// JWKS URL if the resource publishes its own verifying keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// Scopes the resource accepts. Filters what a client can ask
    /// the AS for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
}

/// OAuth client metadata (RFC 7591 Dynamic Client Registration).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OAuthClientMetadata {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_bound_access_tokens: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
}

/// OAuth Authorization Server Metadata (RFC 8414).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OAuthServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_response_iss_parameter_supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_resources: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_metadata_document_supported: Option<bool>,
}

/// Token response from the authorization server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// DID of the authenticated user (ATproto extension).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

/// Pushed Authorization Request response (RFC 9126).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParResponse {
    pub request_uri: String,
    pub expires_in: u64,
}

/// Internal token set with computed expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub issuer: String,
    pub sub: String,
    pub scope: String,
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Intended audience (PDS / resource-server URL) for this token.
    /// Bound via DPoP `htu` claims on all resource-server requests.
    /// `None` on legacy sessions that predate the field; `aud_or_issuer()`
    /// falls back to `issuer` in that case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

impl TokenSet {
    /// Create from a token response. `aud` is the PDS URL the client
    /// discovered during identity resolution.
    pub fn from_response(issuer: &str, aud: Option<&str>, response: &OAuthTokenResponse) -> Self {
        let expires_at = response.expires_in.map(|secs| {
            let dt = chrono::Utc::now() + chrono::Duration::seconds(secs as i64);
            dt.to_rfc3339()
        });

        TokenSet {
            issuer: issuer.to_string(),
            sub: response.sub.clone().unwrap_or_default(),
            scope: response.scope.clone().unwrap_or_default(),
            access_token: response.access_token.clone(),
            refresh_token: response.refresh_token.clone(),
            token_type: response.token_type.clone(),
            expires_at,
            aud: aud.map(str::to_string),
        }
    }

    /// Audience URL for DPoP `htu` binding. Falls back to `issuer` for
    /// legacy token sets that predate the `aud` field.
    pub fn aud_or_issuer(&self) -> &str {
        self.aud.as_deref().unwrap_or(&self.issuer)
    }

    /// Check if the token is expired or about to expire (within buffer seconds).
    pub fn is_expired(&self, buffer_secs: i64) -> bool {
        match &self.expires_at {
            Some(exp) => {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(exp) {
                    let now = chrono::Utc::now();
                    let threshold = now + chrono::Duration::seconds(buffer_secs);
                    dt < threshold
                } else {
                    false
                }
            }
            None => false,
        }
    }

    /// Like `is_expired` but jitters the window by +[0, jitter_secs) so
    /// a fleet of concurrent sessions doesn't stampede the /token
    /// endpoint when their `expires_in` lands in the same second.
    pub fn is_expired_jittered(&self, buffer_secs: i64, jitter_secs: u32) -> bool {
        let jitter = if jitter_secs == 0 {
            0
        } else {
            // `rand::random` returns a uniformly-distributed integer;
            // keep it bounded and deterministic across platforms.
            (rand::random::<u32>() % jitter_secs) as i64
        };
        self.is_expired(buffer_secs + jitter)
    }
}

/// Authorization state stored during the OAuth flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthState {
    pub issuer: String,
    pub verifier: String,
    pub dpop_key: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_state: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_metadata_serde() {
        let meta = OAuthClientMetadata {
            client_id: "https://myapp.example.com/client-metadata.json".into(),
            redirect_uris: vec!["https://myapp.example.com/callback".into()],
            response_types: Some(vec!["code".into()]),
            grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
            scope: Some("atproto transition:generic".into()),
            token_endpoint_auth_method: Some("none".into()),
            token_endpoint_auth_signing_alg: None,
            application_type: Some("web".into()),
            dpop_bound_access_tokens: Some(true),
            client_name: Some("My App".into()),
            client_uri: None,
            logo_uri: None,
        };

        let json = serde_json::to_string_pretty(&meta).unwrap();
        assert!(json.contains("client_id"));
        assert!(json.contains("redirect_uris"));
        let parsed: OAuthClientMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.client_id, meta.client_id);
    }

    #[test]
    fn server_metadata_serde() {
        let json = r#"{
            "issuer": "https://bsky.social",
            "authorization_endpoint": "https://bsky.social/oauth/authorize",
            "token_endpoint": "https://bsky.social/oauth/token",
            "dpop_signing_alg_values_supported": ["ES256"],
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code", "refresh_token"]
        }"#;
        let meta: OAuthServerMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.issuer, "https://bsky.social");
        assert!(meta.pushed_authorization_request_endpoint.is_none());
    }

    #[test]
    fn token_response_serde() {
        let json = r#"{
            "access_token": "eyJ...",
            "token_type": "DPoP",
            "scope": "atproto",
            "refresh_token": "eyJ...",
            "expires_in": 3600,
            "sub": "did:plc:abc123"
        }"#;
        let resp: OAuthTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.token_type, "DPoP");
        assert_eq!(resp.sub.as_deref(), Some("did:plc:abc123"));
        assert_eq!(resp.expires_in, Some(3600));
    }

    #[test]
    fn token_set_from_response() {
        let resp = OAuthTokenResponse {
            access_token: "access".into(),
            token_type: "DPoP".into(),
            scope: Some("atproto".into()),
            refresh_token: Some("refresh".into()),
            expires_in: Some(3600),
            sub: Some("did:plc:test".into()),
        };
        let ts = TokenSet::from_response(
            "https://bsky.social",
            Some("https://pds.example.com"),
            &resp,
        );
        assert_eq!(ts.issuer, "https://bsky.social");
        assert_eq!(ts.aud.as_deref(), Some("https://pds.example.com"));
        assert_eq!(ts.aud_or_issuer(), "https://pds.example.com");
        assert_eq!(ts.sub, "did:plc:test");
        assert!(!ts.is_expired(0));
    }

    #[test]
    fn token_set_aud_falls_back_to_issuer() {
        let resp = OAuthTokenResponse {
            access_token: "a".into(),
            token_type: "DPoP".into(),
            scope: None,
            refresh_token: None,
            expires_in: None,
            sub: None,
        };
        let ts = TokenSet::from_response("https://bsky.social", None, &resp);
        assert!(ts.aud.is_none());
        assert_eq!(ts.aud_or_issuer(), "https://bsky.social");
    }

    #[test]
    fn token_set_expiry_check() {
        let mut ts = TokenSet {
            issuer: "https://bsky.social".into(),
            sub: "did:plc:test".into(),
            scope: "atproto".into(),
            access_token: "access".into(),
            refresh_token: None,
            token_type: "DPoP".into(),
            expires_at: Some("2020-01-01T00:00:00Z".into()),
            aud: None,
        };
        assert!(ts.is_expired(0));

        ts.expires_at = Some("2099-01-01T00:00:00Z".into());
        assert!(!ts.is_expired(0));
    }

    #[test]
    fn par_response_serde() {
        let json =
            r#"{"request_uri": "urn:ietf:params:oauth:request_uri:abc123", "expires_in": 60}"#;
        let par: ParResponse = serde_json::from_str(json).unwrap();
        assert!(par.request_uri.starts_with("urn:"));
        assert_eq!(par.expires_in, 60);
    }
}
