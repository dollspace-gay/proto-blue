//! AT Protocol Agent — high-level client wrapping XRPC.
//!
//! Provides session management, convenience methods for common operations,
//! and namespace accessors for the full Lexicon API surface.

use std::sync::Arc;
use tokio::sync::RwLock;

use proto_blue_xrpc::{CallOptions, HeadersMap, QueryParams, QueryValue, XrpcBody, XrpcClient};

use crate::rich_text::RichText;

/// Session data for an authenticated agent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub did: String,
    pub handle: String,
    pub access_jwt: String,
    pub refresh_jwt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_confirmed: Option<bool>,
}

/// Errors from Agent operations.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("XRPC error: {0}")]
    Xrpc(#[from] proto_blue_xrpc::Error),
    #[error("Not authenticated")]
    NotAuthenticated,
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

/// High-level AT Protocol agent.
///
/// Auth state lives in a single `RwLock<Option<Session>>`. The XRPC client
/// is never mutated after construction — auth headers are passed per-request.
/// This avoids token leaks, giant-lock contention, and split-lock atomicity
/// gaps that arise from storing auth in the client's default headers.
pub struct Agent {
    client: XrpcClient,
    session: Arc<RwLock<Option<Session>>>,
}

impl Agent {
    /// Create a new agent pointing at the given service URL.
    pub fn new(service: impl AsRef<str>) -> Result<Self, AgentError> {
        let client = XrpcClient::new(service)?;
        Ok(Agent {
            client,
            session: Arc::new(RwLock::new(None)),
        })
    }

    /// Get the service URL string.
    pub fn service(&self) -> String {
        self.client.service_url().to_string()
    }

    /// Get the current session's DID, if logged in.
    pub async fn did(&self) -> Option<String> {
        self.session.read().await.as_ref().map(|s| s.did.clone())
    }

    /// Get the current session, if any.
    pub async fn session(&self) -> Option<Session> {
        self.session.read().await.clone()
    }

    // --- Authentication ---

    /// Build per-request `CallOptions` carrying the current access token.
    /// Returns `None` if not authenticated.
    async fn auth_call_options(&self) -> Option<CallOptions> {
        let guard = self.session.read().await;
        guard.as_ref().map(|s| {
            let mut headers = HeadersMap::new();
            headers.insert("Authorization".into(), format!("Bearer {}", s.access_jwt));
            CallOptions {
                encoding: None,
                headers: Some(headers),
            }
        })
    }

    /// Log in with identifier (handle or DID) and password.
    pub async fn login(&self, identifier: &str, password: &str) -> Result<Session, AgentError> {
        let body = serde_json::json!({
            "identifier": identifier,
            "password": password,
        });

        let response = self
            .client
            .procedure(
                "com.atproto.server.createSession",
                None,
                Some(XrpcBody::Json(body)),
                None,
            )
            .await?;

        let session: Session = serde_json::from_value(response.data)?;

        // Atomically commit session in a single write lock
        *self.session.write().await = Some(session.clone());
        Ok(session)
    }

    /// Resume an existing session.
    ///
    /// Verifies the session with the server *before* updating internal state.
    /// If verification fails, the agent remains unauthenticated.
    pub async fn resume_session(&self, session: Session) -> Result<(), AgentError> {
        // Verify the session is valid by calling getSession with the provided token,
        // WITHOUT updating the agent's state first. Use a per-request auth header.
        let mut headers = HeadersMap::new();
        headers.insert(
            "Authorization".into(),
            format!("Bearer {}", session.access_jwt),
        );
        let opts = CallOptions {
            encoding: None,
            headers: Some(headers),
        };
        let response = self
            .client
            .query("com.atproto.server.getSession", None, Some(&opts))
            .await?;
        let verified_did = response
            .data
            .get("did")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Verification succeeded — atomically commit state in a single write lock
        let mut committed = session;
        if let Some(did) = verified_did {
            committed.did = did;
        }
        *self.session.write().await = Some(committed);

        Ok(())
    }

    /// Refresh the current session tokens.
    ///
    /// Uses a per-request header for the refresh call so the refresh JWT is
    /// never exposed as the global auth state. The new session is committed
    /// atomically in a single write lock.
    pub async fn refresh_session(&self) -> Result<Session, AgentError> {
        let refresh_jwt = {
            let sess = self.session.read().await;
            let sess = sess.as_ref().ok_or(AgentError::NotAuthenticated)?;
            sess.refresh_jwt.clone()
        };

        // Use per-request header for refresh — never mutate global auth state
        let mut headers = HeadersMap::new();
        headers.insert("Authorization".into(), format!("Bearer {}", refresh_jwt));
        let opts = CallOptions {
            encoding: None,
            headers: Some(headers),
        };

        let response = self
            .client
            .procedure("com.atproto.server.refreshSession", None, None, Some(&opts))
            .await?;

        let session: Session = serde_json::from_value(response.data)?;

        // Atomically commit new session in a single write lock
        *self.session.write().await = Some(session.clone());
        Ok(session)
    }

    // --- Convenience helpers ---

    /// Ensure the agent is authenticated, returning the DID.
    async fn assert_did(&self) -> Result<String, AgentError> {
        self.did().await.ok_or(AgentError::NotAuthenticated)
    }

    /// Helper: make a query call.
    async fn xrpc_query(
        &self,
        nsid: &str,
        params: Option<&QueryParams>,
    ) -> Result<serde_json::Value, AgentError> {
        let opts = self.auth_call_options().await;
        let response = self.client.query(nsid, params, opts.as_ref()).await?;
        Ok(response.data)
    }

    /// Helper: make a procedure call with JSON body.
    async fn xrpc_procedure(
        &self,
        nsid: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, AgentError> {
        let opts = self.auth_call_options().await;
        let response = self
            .client
            .procedure(nsid, None, Some(XrpcBody::Json(body)), opts.as_ref())
            .await?;
        Ok(response.data)
    }

    /// Helper: create a record.
    async fn create_record(
        &self,
        collection: &str,
        record: serde_json::Value,
    ) -> Result<serde_json::Value, AgentError> {
        let did = self.assert_did().await?;
        let body = serde_json::json!({
            "repo": did,
            "collection": collection,
            "record": record,
        });
        self.xrpc_procedure("com.atproto.repo.createRecord", body)
            .await
    }

    /// Helper: delete a record by AT-URI.
    async fn delete_record(&self, collection: &str, uri: &str) -> Result<(), AgentError> {
        let did = self.assert_did().await?;
        let rkey = uri
            .rsplit('/')
            .next()
            .ok_or_else(|| AgentError::Other("Invalid AT-URI".into()))?;

        let body = serde_json::json!({
            "repo": did,
            "collection": collection,
            "rkey": rkey,
        });
        self.xrpc_procedure("com.atproto.repo.deleteRecord", body)
            .await?;
        Ok(())
    }

    /// Generate an ISO 8601 timestamp with millisecond precision.
    fn now_iso() -> String {
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    /// Resolve a timestamp: use the provided value or generate one.
    fn resolve_timestamp(created_at: Option<&str>) -> String {
        created_at.map(String::from).unwrap_or_else(Self::now_iso)
    }

    // --- Post operations ---

    /// Create a new post.
    ///
    /// If `created_at` is `None`, the current time is used.
    pub async fn post(
        &self,
        text: &str,
        facets: Option<Vec<crate::rich_text::Facet>>,
        created_at: Option<&str>,
    ) -> Result<serde_json::Value, AgentError> {
        let mut record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": text,
            "createdAt": Self::resolve_timestamp(created_at),
        });

        if let Some(facets) = facets {
            record["facets"] = serde_json::to_value(&facets)?;
        }

        self.create_record("app.bsky.feed.post", record).await
    }

    /// Create a post from RichText (includes detected facets).
    pub async fn post_rich(
        &self,
        rt: &RichText,
        created_at: Option<&str>,
    ) -> Result<serde_json::Value, AgentError> {
        let facets = if rt.facets().is_empty() {
            None
        } else {
            Some(rt.facets().to_vec())
        };
        self.post(rt.text(), facets, created_at).await
    }

    /// Delete a post by AT-URI.
    pub async fn delete_post(&self, uri: &str) -> Result<(), AgentError> {
        self.delete_record("app.bsky.feed.post", uri).await
    }

    // --- Like / Repost ---

    /// Like a post.
    ///
    /// If `created_at` is `None`, the current time is used.
    pub async fn like(
        &self,
        uri: &str,
        cid: &str,
        created_at: Option<&str>,
    ) -> Result<serde_json::Value, AgentError> {
        let record = serde_json::json!({
            "$type": "app.bsky.feed.like",
            "subject": { "uri": uri, "cid": cid },
            "createdAt": Self::resolve_timestamp(created_at),
        });
        self.create_record("app.bsky.feed.like", record).await
    }

    /// Unlike a post by AT-URI of the like record.
    pub async fn delete_like(&self, like_uri: &str) -> Result<(), AgentError> {
        self.delete_record("app.bsky.feed.like", like_uri).await
    }

    /// Repost a post.
    ///
    /// If `created_at` is `None`, the current time is used.
    pub async fn repost(
        &self,
        uri: &str,
        cid: &str,
        created_at: Option<&str>,
    ) -> Result<serde_json::Value, AgentError> {
        let record = serde_json::json!({
            "$type": "app.bsky.feed.repost",
            "subject": { "uri": uri, "cid": cid },
            "createdAt": Self::resolve_timestamp(created_at),
        });
        self.create_record("app.bsky.feed.repost", record).await
    }

    /// Delete a repost by AT-URI.
    pub async fn delete_repost(&self, repost_uri: &str) -> Result<(), AgentError> {
        self.delete_record("app.bsky.feed.repost", repost_uri).await
    }

    // --- Follow ---

    /// Follow a user by DID.
    ///
    /// If `created_at` is `None`, the current time is used.
    pub async fn follow(
        &self,
        subject_did: &str,
        created_at: Option<&str>,
    ) -> Result<serde_json::Value, AgentError> {
        let record = serde_json::json!({
            "$type": "app.bsky.graph.follow",
            "subject": subject_did,
            "createdAt": Self::resolve_timestamp(created_at),
        });
        self.create_record("app.bsky.graph.follow", record).await
    }

    /// Unfollow by AT-URI of the follow record.
    pub async fn delete_follow(&self, follow_uri: &str) -> Result<(), AgentError> {
        self.delete_record("app.bsky.graph.follow", follow_uri)
            .await
    }

    // --- Query helpers ---

    /// Get a user's profile.
    pub async fn get_profile(&self, actor: &str) -> Result<serde_json::Value, AgentError> {
        let mut params = QueryParams::new();
        params.insert("actor".into(), QueryValue::String(actor.into()));
        self.xrpc_query("app.bsky.actor.getProfile", Some(&params))
            .await
    }

    /// Get the home timeline.
    pub async fn get_timeline(
        &self,
        limit: Option<i64>,
        cursor: Option<&str>,
    ) -> Result<serde_json::Value, AgentError> {
        let mut params = QueryParams::new();
        if let Some(limit) = limit {
            params.insert("limit".into(), QueryValue::Integer(limit));
        }
        if let Some(cursor) = cursor {
            params.insert("cursor".into(), QueryValue::String(cursor.into()));
        }
        self.xrpc_query("app.bsky.feed.getTimeline", Some(&params))
            .await
    }

    /// Get a post thread.
    pub async fn get_post_thread(
        &self,
        uri: &str,
        depth: Option<i64>,
    ) -> Result<serde_json::Value, AgentError> {
        let mut params = QueryParams::new();
        params.insert("uri".into(), QueryValue::String(uri.into()));
        if let Some(depth) = depth {
            params.insert("depth".into(), QueryValue::Integer(depth));
        }
        self.xrpc_query("app.bsky.feed.getPostThread", Some(&params))
            .await
    }

    /// Search actors.
    pub async fn search_actors(
        &self,
        query: &str,
        limit: Option<i64>,
    ) -> Result<serde_json::Value, AgentError> {
        let mut params = QueryParams::new();
        params.insert("q".into(), QueryValue::String(query.into()));
        if let Some(limit) = limit {
            params.insert("limit".into(), QueryValue::Integer(limit));
        }
        self.xrpc_query("app.bsky.actor.searchActors", Some(&params))
            .await
    }

    /// Resolve a handle to a DID.
    pub async fn resolve_handle(&self, handle: &str) -> Result<String, AgentError> {
        let mut params = QueryParams::new();
        params.insert("handle".into(), QueryValue::String(handle.into()));
        let data = self
            .xrpc_query("com.atproto.identity.resolveHandle", Some(&params))
            .await?;
        data.get("did")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| AgentError::Other("Missing DID in response".into()))
    }

    /// Get notifications.
    pub async fn list_notifications(
        &self,
        limit: Option<i64>,
        cursor: Option<&str>,
    ) -> Result<serde_json::Value, AgentError> {
        let mut params = QueryParams::new();
        if let Some(limit) = limit {
            params.insert("limit".into(), QueryValue::Integer(limit));
        }
        if let Some(cursor) = cursor {
            params.insert("cursor".into(), QueryValue::String(cursor.into()));
        }
        self.xrpc_query("app.bsky.notification.listNotifications", Some(&params))
            .await
    }

    /// Upload a blob (image, video, etc.).
    pub async fn upload_blob(
        &self,
        data: Vec<u8>,
        content_type: &str,
    ) -> Result<serde_json::Value, AgentError> {
        let mut headers = HeadersMap::new();
        headers.insert("Content-Type".into(), content_type.into());

        // Add auth header from session
        if let Some(sess) = self.session.read().await.as_ref() {
            headers.insert(
                "Authorization".into(),
                format!("Bearer {}", sess.access_jwt),
            );
        }

        let opts = CallOptions {
            encoding: Some(content_type.to_string()),
            headers: Some(headers),
        };

        let response = self
            .client
            .procedure(
                "com.atproto.repo.uploadBlob",
                None,
                Some(XrpcBody::Bytes(data)),
                Some(&opts),
            )
            .await?;

        Ok(response.data)
    }

    /// Describe the server.
    pub async fn describe_server(&self) -> Result<serde_json::Value, AgentError> {
        self.xrpc_query("com.atproto.server.describeServer", None)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_creation() {
        let _agent = Agent::new("https://bsky.social").unwrap();
    }

    #[test]
    fn session_serde_roundtrip() {
        let session = Session {
            did: "did:plc:abc123".to_string(),
            handle: "alice.bsky.social".to_string(),
            access_jwt: "eyJ...".to_string(),
            refresh_jwt: "eyJ...".to_string(),
            email: Some("alice@example.com".to_string()),
            email_confirmed: Some(true),
        };

        let json = serde_json::to_string(&session).unwrap();
        let parsed: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.did, "did:plc:abc123");
        assert_eq!(parsed.handle, "alice.bsky.social");
        assert_eq!(parsed.email, Some("alice@example.com".to_string()));
    }

    #[test]
    fn agent_error_display() {
        let err = AgentError::NotAuthenticated;
        assert_eq!(err.to_string(), "Not authenticated");

        let err = AgentError::Other("test error".into());
        assert_eq!(err.to_string(), "test error");
    }

    #[tokio::test]
    async fn agent_no_session_by_default() {
        let agent = Agent::new("https://bsky.social").unwrap();
        assert!(agent.did().await.is_none());
        assert!(agent.session().await.is_none());
    }

    #[tokio::test]
    async fn agent_assert_did_fails_when_not_logged_in() {
        let agent = Agent::new("https://bsky.social").unwrap();
        let err = agent.assert_did().await.unwrap_err();
        assert!(matches!(err, AgentError::NotAuthenticated));
    }

    #[test]
    fn now_iso_format() {
        let ts = Agent::now_iso();
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
    }

    #[test]
    fn resolve_timestamp_with_provided() {
        let ts = Agent::resolve_timestamp(Some("2024-01-15T12:00:00.000Z"));
        assert_eq!(ts, "2024-01-15T12:00:00.000Z");
    }

    #[test]
    fn resolve_timestamp_without_provided() {
        let ts = Agent::resolve_timestamp(None);
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
    }

    #[test]
    fn service_url_accessible_without_async() {
        let agent = Agent::new("https://bsky.social").unwrap();
        assert_eq!(agent.service(), "https://bsky.social/");
    }

    #[tokio::test]
    async fn auth_call_options_none_when_not_authenticated() {
        let agent = Agent::new("https://bsky.social").unwrap();
        assert!(agent.auth_call_options().await.is_none());
    }
}
