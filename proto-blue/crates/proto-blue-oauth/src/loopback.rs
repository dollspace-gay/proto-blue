//! Loopback client ID parsing (AT Protocol profile).
//!
//! AT Protocol's OAuth profile defines a special class of "loopback"
//! clients — CLIs, desktop apps, and any other confidential client
//! running on the user's own machine — identified by a client ID of
//! the form:
//!
//! ```text
//! http://localhost[/path][?scope=…&redirect_uri=…]
//! ```
//!
//! These clients don't publish a client-metadata document. Instead,
//! the URL *is* the metadata: the authorization server synthesizes a
//! metadata object from the query parameters at authorization time.
//!
//! This module provides [`LoopbackClientId`] which parses such URLs
//! and [`loopback_client_metadata`] which synthesizes the implicit
//! [`OAuthClientMetadata`] a client needs to drive its own flow (same
//! shape the AS would build on its side).
//!
//! Rules (from the atproto spec):
//! - Scheme MUST be `http`.
//! - Host MUST be `localhost`, `127.0.0.1`, or `[::1]`.
//! - `scope` query parameter is optional. When absent, defaults to
//!   `atproto`.
//! - `redirect_uri` query parameter MAY repeat and MUST each be an
//!   `http://127.0.0.1` URI (loopback interface, not the literal
//!   "localhost" hostname — per RFC 8252 §7.3).
//! - `token_endpoint_auth_method` is fixed at `"none"` — loopback
//!   clients are public and use DPoP for request-binding.
//! - `dpop_bound_access_tokens` is fixed at `true`.

use url::Url;

use crate::error::OAuthError;
use crate::types::OAuthClientMetadata;

/// A parsed loopback client identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopbackClientId {
    /// The original client ID URL.
    pub client_id: String,
    /// Scope requested via the `scope` query parameter, or `"atproto"`
    /// if none was given.
    pub scope: String,
    /// One or more redirect URIs. Non-empty; defaults to a single
    /// `http://127.0.0.1/` when the URL didn't specify any.
    pub redirect_uris: Vec<String>,
}

impl LoopbackClientId {
    /// Parse a loopback client ID. Returns `Err` if the URL isn't a
    /// valid loopback identifier (non-http scheme, non-loopback host,
    /// malformed redirect URI, etc.).
    pub fn parse(client_id: &str) -> Result<Self, OAuthError> {
        let url = Url::parse(client_id)
            .map_err(|e| OAuthError::InvalidClientMetadata(format!("invalid client_id URL: {e}")))?;

        if url.scheme() != "http" {
            return Err(OAuthError::InvalidClientMetadata(format!(
                "loopback client_id must use http scheme, got {}",
                url.scheme()
            )));
        }

        let host = url.host_str().ok_or_else(|| {
            OAuthError::InvalidClientMetadata("loopback client_id is missing host".into())
        })?;
        if !is_loopback_host(host) {
            return Err(OAuthError::InvalidClientMetadata(format!(
                "loopback client_id host must be localhost/127.0.0.1/[::1], got {host}"
            )));
        }

        let mut scope = "atproto".to_string();
        let mut redirect_uris = Vec::new();
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "scope" => scope = value.into_owned(),
                "redirect_uri" => {
                    let ru = Url::parse(value.as_ref()).map_err(|e| {
                        OAuthError::InvalidClientMetadata(format!(
                            "loopback redirect_uri `{value}`: {e}"
                        ))
                    })?;
                    validate_redirect_uri(&ru)?;
                    redirect_uris.push(value.into_owned());
                }
                _ => {
                    // Unknown query parameters are ignored — the AS
                    // applies the same relaxed policy when it
                    // synthesizes metadata from the URL.
                }
            }
        }

        if redirect_uris.is_empty() {
            // No explicit redirect — default to the AT Protocol
            // reference implementation's fallback: a port-agnostic
            // loopback that the AS will match against any
            // `http://127.0.0.1:<port>/` the client actually listens on.
            redirect_uris.push("http://127.0.0.1/".to_string());
        }

        Ok(LoopbackClientId {
            client_id: client_id.to_string(),
            scope,
            redirect_uris,
        })
    }
}

/// True iff `client_id` looks like a loopback client identifier.
/// Returns false on parse errors — callers can cheaply pre-check
/// before invoking [`LoopbackClientId::parse`].
pub fn is_loopback_client_id(client_id: &str) -> bool {
    Url::parse(client_id)
        .map(|u| u.scheme() == "http" && u.host_str().is_some_and(is_loopback_host))
        .unwrap_or(false)
}

/// Synthesize the implicit [`OAuthClientMetadata`] for a loopback
/// client ID. Mirrors what the authorization server will build on its
/// side: public client, DPoP-bound, `token_endpoint_auth_method=none`.
pub fn loopback_client_metadata(client_id: &str) -> Result<OAuthClientMetadata, OAuthError> {
    let parsed = LoopbackClientId::parse(client_id)?;
    Ok(OAuthClientMetadata {
        client_id: parsed.client_id,
        redirect_uris: parsed.redirect_uris,
        response_types: Some(vec!["code".into()]),
        grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
        scope: Some(parsed.scope),
        token_endpoint_auth_method: Some("none".into()),
        token_endpoint_auth_signing_alg: None,
        application_type: Some("native".into()),
        dpop_bound_access_tokens: Some(true),
        client_name: None,
        client_uri: None,
        logo_uri: None,
    })
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

fn validate_redirect_uri(url: &Url) -> Result<(), OAuthError> {
    if url.scheme() != "http" {
        return Err(OAuthError::InvalidClientMetadata(format!(
            "loopback redirect_uri must use http scheme, got {}",
            url.scheme()
        )));
    }
    let host = url.host_str().ok_or_else(|| {
        OAuthError::InvalidClientMetadata("loopback redirect_uri has no host".into())
    })?;
    // Per RFC 8252 §7.3, native apps MUST use the 127.0.0.1 / [::1]
    // *literal loopback interface* — not the "localhost" hostname,
    // which is subject to DNS resolution and may not reach the local
    // machine. We enforce that on redirect URIs even though we accept
    // "localhost" as the client-id host (where no resolution happens).
    if host != "127.0.0.1" && host != "[::1]" && host != "::1" {
        return Err(OAuthError::InvalidClientMetadata(format!(
            "loopback redirect_uri host must be 127.0.0.1 or [::1], got {host}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_loopback_client_id_matches_loopback_hosts() {
        assert!(is_loopback_client_id("http://localhost/"));
        assert!(is_loopback_client_id("http://127.0.0.1/"));
        assert!(is_loopback_client_id("http://localhost:8080/"));

        assert!(!is_loopback_client_id("https://app.example.com/metadata.json"));
        assert!(!is_loopback_client_id("http://example.com/"));
        assert!(!is_loopback_client_id("not a url"));
    }

    #[test]
    fn parse_defaults_scope_and_redirect() {
        let c = LoopbackClientId::parse("http://localhost/").unwrap();
        assert_eq!(c.scope, "atproto");
        assert_eq!(c.redirect_uris, vec!["http://127.0.0.1/"]);
    }

    #[test]
    fn parse_honors_scope_and_redirect_uri_query_params() {
        let c = LoopbackClientId::parse(
            "http://localhost/?scope=atproto%20transition:generic&redirect_uri=http://127.0.0.1:8080/cb",
        )
        .unwrap();
        assert_eq!(c.scope, "atproto transition:generic");
        assert_eq!(c.redirect_uris, vec!["http://127.0.0.1:8080/cb"]);
    }

    #[test]
    fn parse_accepts_multiple_redirect_uris() {
        let c = LoopbackClientId::parse(
            "http://localhost/?redirect_uri=http://127.0.0.1:8080/cb&redirect_uri=http://127.0.0.1:9090/cb",
        )
        .unwrap();
        assert_eq!(c.redirect_uris.len(), 2);
    }

    #[test]
    fn parse_rejects_non_http_scheme() {
        let err = LoopbackClientId::parse("https://localhost/").unwrap_err();
        assert!(
            matches!(err, OAuthError::InvalidClientMetadata(msg) if msg.contains("http scheme")),
            "expected scheme error"
        );
    }

    #[test]
    fn parse_rejects_non_loopback_host() {
        let err = LoopbackClientId::parse("http://example.com/").unwrap_err();
        assert!(matches!(err, OAuthError::InvalidClientMetadata(_)));
    }

    #[test]
    fn parse_rejects_localhost_redirect_uri() {
        // "localhost" as a *redirect URI* host is RFC 8252 §7.3 forbidden.
        let err = LoopbackClientId::parse(
            "http://localhost/?redirect_uri=http://localhost:8080/cb",
        )
        .unwrap_err();
        assert!(matches!(err, OAuthError::InvalidClientMetadata(_)));
    }

    #[test]
    fn loopback_client_metadata_is_public_dpop_bound() {
        let meta = loopback_client_metadata("http://localhost:8080/").unwrap();
        assert_eq!(meta.client_id, "http://localhost:8080/");
        assert_eq!(meta.token_endpoint_auth_method.as_deref(), Some("none"));
        assert_eq!(meta.dpop_bound_access_tokens, Some(true));
        assert_eq!(meta.application_type.as_deref(), Some("native"));
        assert_eq!(meta.scope.as_deref(), Some("atproto"));
        assert!(!meta.redirect_uris.is_empty());
    }
}
