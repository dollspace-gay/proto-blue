//! OAuth 2.0 type definitions for AT Protocol.

use serde::{Deserialize, Serialize};

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
}

impl TokenSet {
    /// Create from a token response.
    pub fn from_response(issuer: &str, response: &OAuthTokenResponse) -> Self {
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
        }
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
        let ts = TokenSet::from_response("https://bsky.social", &resp);
        assert_eq!(ts.issuer, "https://bsky.social");
        assert_eq!(ts.sub, "did:plc:test");
        assert!(!ts.is_expired(0));
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
