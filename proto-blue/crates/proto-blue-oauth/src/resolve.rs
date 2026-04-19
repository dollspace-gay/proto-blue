//! End-to-end identity → AS resolution for `OAuthClient::authorize`.
//!
//! The atproto OAuth profile lets a caller kick off a login flow with
//! a handle (`alice.bsky.social`), a DID (`did:plc:…`), or a PDS URL
//! directly. This module resolves any of those into the
//! `(pds_url, server_metadata)` pair `authorize()` needs:
//!
//! ```text
//! handle ───► DID ───► DID document ───► PDS URL
//!                                         │
//!                                         ▼
//!                                    /.well-known/oauth-protected-resource
//!                                         │
//!                                         ▼
//!                                       authorization_server
//!                                         │
//!                                         ▼
//!                                    /.well-known/oauth-authorization-server
//!                                         │
//!                                         ▼
//!                                    OAuthServerMetadata
//! ```
//!
//! The `resolve_input` orchestration is gated behind the
//! `identity-resolver` feature so the default server-only / minimal
//! build doesn't pull in DNS + PLC deps. The [`verify_token_sub`]
//! helper is unconditionally available since it's just an equality
//! check with a useful error message.

use crate::error::OAuthError;

#[cfg(feature = "identity-resolver")]
use proto_blue_identity::IdResolver;

#[cfg(feature = "identity-resolver")]
use crate::client::OAuthClient;

/// Resolved OAuth entry point for a given input (handle / DID / PDS
/// URL). Hand this to [`OAuthClient::authorize`] (for the server
/// metadata) and onto the eventual [`crate::TokenSet`] (for `aud`).
#[derive(Debug, Clone)]
pub struct ResolvedInput {
    /// The DID of the subject, when identity resolution produced one
    /// (`None` when the input was a bare PDS URL). Used by
    /// post-token `sub` verification.
    pub did: Option<String>,
    /// The resource-server (PDS) URL. Becomes `TokenSet.aud` and the
    /// `htu` binding on resource-server DPoP proofs.
    pub pds_url: String,
    /// The authorization server metadata the client will drive the
    /// flow against.
    pub server_metadata: crate::types::OAuthServerMetadata,
}

/// Resolve a handle, DID, or PDS URL to the `(did?, pds_url,
/// server_metadata)` tuple a login flow needs.
///
/// Input heuristics:
/// - Starts with `"did:"` → treated as a DID; resolve to DID
///   document and extract the PDS endpoint.
/// - Starts with `"http://"` or `"https://"` → treated as a PDS URL
///   (or loopback AS, for tests); skips identity resolution entirely.
/// - Otherwise → treated as a handle; verified resolution
///   (handle → DID → document with alsoKnownAs check).
#[cfg(feature = "identity-resolver")]
pub async fn resolve_input(
    resolver: &IdResolver,
    client: &OAuthClient,
    input: &str,
) -> Result<ResolvedInput, OAuthError> {
    let (did, pds_url) = if input.starts_with("did:") {
        let doc = resolver
            .did
            .ensure_resolve(input, /*force_refresh=*/ false)
            .await
            .map_err(|e| OAuthError::Other(format!("DID resolve failed: {e}")))?;
        let pds = proto_blue_common::get_pds_endpoint(&doc).ok_or_else(|| {
            OAuthError::Other(format!("DID document {input:?} has no PDS endpoint"))
        })?;
        (Some(input.to_string()), pds.to_string())
    } else if input.starts_with("http://") || input.starts_with("https://") {
        (None, input.trim_end_matches('/').to_string())
    } else {
        let (did, doc) = resolver
            .resolve_handle_verified(input)
            .await
            .map_err(|e| OAuthError::Other(format!("handle resolve failed: {e}")))?;
        let pds = proto_blue_common::get_pds_endpoint(&doc).ok_or_else(|| {
            OAuthError::Other(format!("DID document {did:?} has no PDS endpoint"))
        })?;
        (Some(did), pds.to_string())
    };

    let resource = client.discover_resource(&pds_url).await?;
    let auth_servers = resource.authorization_servers.as_deref().unwrap_or(&[]);
    let as_url = auth_servers.first().ok_or_else(|| {
        OAuthError::Other(format!(
            "PDS {pds_url:?} resource metadata has no authorization_servers"
        ))
    })?;
    let server_metadata = client.discover_server(as_url).await?;

    Ok(ResolvedInput {
        did,
        pds_url,
        server_metadata,
    })
}

/// Post-token check: confirm the `sub` the AS returned matches the
/// DID we resolved up-front. Catches a compromised AS handing back a
/// token for a different user than the client thought it was logging
/// in.
///
/// When the input didn't produce a DID (bare PDS URL flow), there's
/// nothing to compare against — the function returns `Ok(())`.
pub fn verify_token_sub(
    expected: Option<&str>,
    token_sub: &str,
) -> Result<(), OAuthError> {
    match expected {
        None => Ok(()),
        Some(did) if did == token_sub => Ok(()),
        Some(did) => Err(OAuthError::Other(format!(
            "token `sub` mismatch: expected {did:?}, got {token_sub:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_token_sub_accepts_match() {
        verify_token_sub(Some("did:plc:abc"), "did:plc:abc").unwrap();
    }

    #[test]
    fn verify_token_sub_accepts_missing_expected() {
        verify_token_sub(None, "did:plc:abc").unwrap();
    }

    #[test]
    fn verify_token_sub_rejects_mismatch() {
        let err = verify_token_sub(Some("did:plc:abc"), "did:plc:xyz").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("did:plc:abc"), "msg={msg}");
        assert!(msg.contains("did:plc:xyz"), "msg={msg}");
    }
}
