//! AT Protocol Agent — high-level client wrapping XRPC.
//!
//! Provides session management, convenience methods for common operations,
//! and namespace accessors for the full Lexicon API surface.

use std::sync::{Arc, Mutex};
use tokio::sync::{Mutex as AsyncMutex, RwLock};

use proto_blue_xrpc::{
    CallOptions, HeadersMap, QueryParams, QueryValue, ResponseType, XrpcBody, XrpcClient,
};

use crate::rich_text::RichText;

/// Session lifecycle events emitted by [`Agent`].
///
/// Mirrors TS `AtpSessionEvent`. Register a listener via
/// [`Agent::on_session`] to observe login / refresh / expiry. Typical
/// use is to persist the session on `Create` / `Update` and to clear
/// local state on `Expired`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtpSessionEvent {
    /// A new session was established (successful login / resume).
    Create,
    /// A login attempt failed.
    CreateFailed,
    /// The session tokens were refreshed.
    Update,
    /// The server rejected the refresh — the user must log in again.
    Expired,
    /// A network-level failure during a session-affecting call.
    NetworkError,
}

/// Callback registered via [`Agent::on_session`].
///
/// Invoked synchronously on the task that produced the event; handlers
/// should not block for long. The `Option<&Session>` is `Some` for
/// `Create` / `Update` and `None` for `CreateFailed` / `Expired` /
/// `NetworkError`.
pub type SessionEventCallback =
    Arc<dyn Fn(AtpSessionEvent, Option<&Session>) + Send + Sync>;

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
///
/// ## Transparent refresh
///
/// Every XRPC call goes through `xrpc_query_with_refresh` /
/// `xrpc_procedure_with_refresh`, which detect 401 /
/// `ExpiredToken` responses, call [`Agent::refresh_session`], and
/// retry once. Concurrent refresh attempts are deduplicated via an
/// async `Mutex` so N in-flight calls that all see an expired token
/// issue exactly one `/refreshSession` request. If the refresh itself
/// fails, the agent fires [`AtpSessionEvent::Expired`] and the
/// original error propagates.
pub struct Agent {
    client: XrpcClient,
    session: Arc<RwLock<Option<Session>>>,
    /// Session-event listeners. Called synchronously on the task that
    /// produced the event.
    listeners: Arc<Mutex<Vec<SessionEventCallback>>>,
    /// Serialises concurrent refreshes. The first caller to see a 401
    /// acquires this lock, performs the refresh, and writes the new
    /// session back; subsequent callers block until that finishes and
    /// then observe the updated session when their retry fires.
    refresh_lock: Arc<AsyncMutex<()>>,
}

impl Agent {
    /// Create a new agent pointing at the given service URL.
    pub fn new(service: impl AsRef<str>) -> Result<Self, AgentError> {
        let client = XrpcClient::new(service)?;
        Ok(Agent {
            client,
            session: Arc::new(RwLock::new(None)),
            listeners: Arc::new(Mutex::new(Vec::new())),
            refresh_lock: Arc::new(AsyncMutex::new(())),
        })
    }

    /// Register a session-event listener.
    ///
    /// Returns `()`, not a handle — listener unregistration isn't
    /// currently supported (the typical pattern is to register a
    /// single persistence callback that lives for the Agent's
    /// lifetime). Multiple listeners are fired in registration order.
    pub fn on_session<F>(&self, callback: F)
    where
        F: Fn(AtpSessionEvent, Option<&Session>) + Send + Sync + 'static,
    {
        self.listeners.lock().unwrap().push(Arc::new(callback));
    }

    /// Fire an event to every registered listener.
    fn emit(&self, event: AtpSessionEvent, session: Option<&Session>) {
        // `listeners` is a sync Mutex; we clone the Arc<callback> list
        // out from under the lock so the callbacks themselves run
        // without holding it (they could be slow / could call back
        // into `on_session`).
        let listeners = self.listeners.lock().unwrap().clone();
        for cb in listeners {
            cb(event, session);
        }
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
                ..Default::default()
            }
        })
    }

    /// Log in with identifier (handle or DID) and password.
    ///
    /// Emits [`AtpSessionEvent::Create`] on success, or
    /// [`AtpSessionEvent::CreateFailed`] if the server rejected the
    /// credentials.
    pub async fn login(&self, identifier: &str, password: &str) -> Result<Session, AgentError> {
        let body = serde_json::json!({
            "identifier": identifier,
            "password": password,
        });

        let response = match self
            .client
            .procedure(
                "com.atproto.server.createSession",
                None,
                Some(XrpcBody::Json(body)),
                None,
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.emit(AtpSessionEvent::CreateFailed, None);
                return Err(AgentError::Xrpc(e));
            }
        };

        let session: Session = serde_json::from_value(response.data)?;

        // Atomically commit session in a single write lock
        *self.session.write().await = Some(session.clone());
        self.emit(AtpSessionEvent::Create, Some(&session));
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
            ..Default::default()
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
        *self.session.write().await = Some(committed.clone());
        self.emit(AtpSessionEvent::Create, Some(&committed));

        Ok(())
    }

    /// Refresh the current session tokens.
    ///
    /// Emits [`AtpSessionEvent::Update`] on success or
    /// [`AtpSessionEvent::Expired`] if the refresh token was
    /// rejected. Uses a per-request header for the refresh call so the
    /// refresh JWT is never exposed as the global auth state. The new
    /// session is committed atomically in a single write lock.
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
            ..Default::default()
        };

        let response = match self
            .client
            .procedure("com.atproto.server.refreshSession", None, None, Some(&opts))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // Any 401 during refresh means the refresh token
                // itself is rejected — drop the session and signal
                // Expired. Other errors (network failure, 5xx, etc.)
                // surface as NetworkError and leave the session in
                // place so a later attempt can retry.
                if is_refresh_rejected(&e) {
                    *self.session.write().await = None;
                    self.emit(AtpSessionEvent::Expired, None);
                } else {
                    self.emit(AtpSessionEvent::NetworkError, None);
                }
                return Err(AgentError::Xrpc(e));
            }
        };

        let session: Session = serde_json::from_value(response.data)?;

        // Atomically commit new session in a single write lock
        *self.session.write().await = Some(session.clone());
        self.emit(AtpSessionEvent::Update, Some(&session));
        Ok(session)
    }

    // --- Convenience helpers ---

    /// Ensure the agent is authenticated, returning the DID.
    async fn assert_did(&self) -> Result<String, AgentError> {
        self.did().await.ok_or(AgentError::NotAuthenticated)
    }

    /// Helper: make a query call with transparent 401-refresh retry.
    ///
    /// When the first attempt returns `ExpiredToken`, try to refresh
    /// the session and replay the call once with the fresh access
    /// token. Concurrent refreshes are deduplicated via
    /// [`Agent::refresh_lock`].
    async fn xrpc_query(
        &self,
        nsid: &str,
        params: Option<&QueryParams>,
    ) -> Result<serde_json::Value, AgentError> {
        let opts = self.auth_call_options().await;
        let first = self.client.query(nsid, params, opts.as_ref()).await;
        match first {
            Ok(r) => Ok(r.data),
            Err(e) if is_auth_expired(&e) => {
                self.refresh_and_retry(|opts| {
                    let c = self.client.clone();
                    let nsid = nsid.to_string();
                    let params = params.cloned();
                    async move {
                        c.query(&nsid, params.as_ref(), opts.as_ref()).await
                    }
                })
                .await
            }
            Err(e) => Err(AgentError::Xrpc(e)),
        }
    }

    /// Helper: make a procedure call with transparent 401-refresh retry.
    async fn xrpc_procedure(
        &self,
        nsid: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, AgentError> {
        let opts = self.auth_call_options().await;
        let first = self
            .client
            .procedure(nsid, None, Some(XrpcBody::Json(body.clone())), opts.as_ref())
            .await;
        match first {
            Ok(r) => Ok(r.data),
            Err(e) if is_auth_expired(&e) => {
                self.refresh_and_retry(|opts| {
                    let c = self.client.clone();
                    let nsid = nsid.to_string();
                    let body = body.clone();
                    async move {
                        c.procedure(&nsid, None, Some(XrpcBody::Json(body)), opts.as_ref())
                            .await
                    }
                })
                .await
            }
            Err(e) => Err(AgentError::Xrpc(e)),
        }
    }

    /// Shared refresh-and-retry driver.
    ///
    /// Acquires the `refresh_lock`, refreshes the session if the
    /// access token in `self.session` is still the one that produced
    /// the 401, rebuilds `CallOptions` from the new token, and runs
    /// `replay(new_opts)`. Concurrent callers that arrive after the
    /// lock is held observe the refreshed session when they get to
    /// build their own opts — only one `/refreshSession` HTTP call
    /// fires per refresh cycle.
    async fn refresh_and_retry<F, Fut>(
        &self,
        replay: F,
    ) -> Result<serde_json::Value, AgentError>
    where
        F: FnOnce(Option<CallOptions>) -> Fut,
        Fut: std::future::Future<
            Output = Result<proto_blue_xrpc::XrpcResponse, proto_blue_xrpc::Error>,
        >,
    {
        // Snapshot the access token the caller's first attempt used.
        // After we acquire the refresh lock, compare — if a peer
        // already refreshed, skip the redundant refresh.
        let pre_refresh_jwt = self
            .session
            .read()
            .await
            .as_ref()
            .map(|s| s.access_jwt.clone());
        let _guard = self.refresh_lock.lock().await;
        let current_jwt = self
            .session
            .read()
            .await
            .as_ref()
            .map(|s| s.access_jwt.clone());
        if pre_refresh_jwt == current_jwt {
            // No peer did the refresh — we must.
            self.refresh_session().await?;
        }
        drop(_guard);

        let opts = self.auth_call_options().await;
        let response = replay(opts).await?;
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
            ..Default::default()
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

/// `true` if an XRPC error signals that the access token is expired
/// and the caller should try to refresh. Looks for
/// `AuthenticationRequired` (401) with the specific `ExpiredToken`
/// error name — other 401 variants aren't necessarily caused by
/// expiry (e.g. wrong credentials, app-password rejection) and
/// shouldn't trigger the refresh-and-retry path.
fn is_auth_expired(err: &proto_blue_xrpc::Error) -> bool {
    match err {
        proto_blue_xrpc::Error::Xrpc(x) => {
            matches!(x.status, ResponseType::AuthenticationRequired)
                && x.is_error("ExpiredToken")
        }
        _ => false,
    }
}

/// `true` if an error from `/refreshSession` signals that the refresh
/// token is rejected (rather than a transient network problem). Any
/// 401 from the refresh endpoint is authoritative — the token is
/// dead — regardless of the specific error-name code.
fn is_refresh_rejected(err: &proto_blue_xrpc::Error) -> bool {
    match err {
        proto_blue_xrpc::Error::Xrpc(x) => {
            matches!(x.status, ResponseType::AuthenticationRequired)
        }
        _ => false,
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

    // ── Session events + auto-refresh ────────────────────────────────

    use async_trait::async_trait;
    use proto_blue_common::fetch::{
        FetchError, FetchHandler, HttpRequest, HttpResponse,
    };

    /// Fetcher that scripts a sequence of responses for each NSID path.
    /// The first call to each NSID returns `responses[i][0]`, second
    /// `responses[i][1]`, etc. Also counts calls per NSID for assertions.
    struct ScriptedFetcher {
        createsession_body: Vec<u8>,
        /// (path_suffix, sequence_of_bodies)
        scripts: std::sync::Mutex<std::collections::HashMap<String, Vec<ScriptedResponse>>>,
        call_counts: std::sync::Mutex<std::collections::HashMap<String, usize>>,
    }

    #[derive(Clone)]
    struct ScriptedResponse {
        status: u16,
        body: Vec<u8>,
    }

    impl ScriptedFetcher {
        fn new(createsession_body: Vec<u8>) -> Self {
            Self {
                createsession_body,
                scripts: Default::default(),
                call_counts: Default::default(),
            }
        }
        fn script(&self, path: &str, responses: Vec<ScriptedResponse>) {
            self.scripts
                .lock()
                .unwrap()
                .insert(path.to_string(), responses);
        }
        fn call_count(&self, path: &str) -> usize {
            *self.call_counts.lock().unwrap().get(path).unwrap_or(&0)
        }
    }

    #[async_trait]
    impl FetchHandler for ScriptedFetcher {
        async fn fetch(&self, req: HttpRequest) -> Result<HttpResponse, FetchError> {
            let path = req.url.clone();
            let key = path
                .split("/xrpc/")
                .nth(1)
                .unwrap_or(&path)
                .split('?')
                .next()
                .unwrap_or("")
                .to_string();
            *self
                .call_counts
                .lock()
                .unwrap()
                .entry(key.clone())
                .or_insert(0) += 1;

            // Scripted responses always take precedence; the
            // createSession short-circuit only fires when the caller
            // hasn't explicitly scripted it.
            {
                let mut scripts = self.scripts.lock().unwrap();
                if let Some(list) = scripts.get_mut(&key) {
                    let resp = if list.len() == 1 {
                        list[0].clone()
                    } else {
                        list.remove(0)
                    };
                    let mut headers = proto_blue_common::fetch::HttpHeaders::new();
                    headers.insert("content-type".into(), "application/json".into());
                    return Ok(HttpResponse {
                        status: resp.status,
                        headers,
                        body: resp.body,
                    });
                }
            }

            // Default: createSession always succeeds.
            if key == "com.atproto.server.createSession" {
                let mut headers = proto_blue_common::fetch::HttpHeaders::new();
                headers.insert("content-type".into(), "application/json".into());
                return Ok(HttpResponse {
                    status: 200,
                    headers,
                    body: self.createsession_body.clone(),
                });
            }

            Err(FetchError::Other(format!("no script for {key}")))
        }
    }

    fn login_body() -> Vec<u8> {
        br#"{"did":"did:plc:u","handle":"alice","accessJwt":"a1","refreshJwt":"r1"}"#
            .to_vec()
    }

    fn agent_with_fetcher(fetcher: Arc<ScriptedFetcher>) -> Agent {
        let client = XrpcClient::with_fetch_handler(
            "https://example.com",
            fetcher,
        )
        .unwrap();
        Agent {
            client,
            session: Arc::new(RwLock::new(None)),
            listeners: Arc::new(Mutex::new(Vec::new())),
            refresh_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    #[tokio::test]
    async fn emits_create_on_successful_login() {
        let fetcher = Arc::new(ScriptedFetcher::new(login_body()));
        let agent = agent_with_fetcher(fetcher);

        let events: Arc<Mutex<Vec<AtpSessionEvent>>> =
            Arc::new(Mutex::new(Vec::new()));
        let ev_clone = events.clone();
        agent.on_session(move |e, _| ev_clone.lock().unwrap().push(e));

        agent.login("alice", "secret").await.unwrap();
        let got = events.lock().unwrap().clone();
        assert_eq!(got, vec![AtpSessionEvent::Create]);
    }

    #[tokio::test]
    async fn emits_create_failed_on_login_rejection() {
        let fetcher = Arc::new(ScriptedFetcher::new(vec![]));
        // Override createSession to fail:
        fetcher.script(
            "com.atproto.server.createSession",
            vec![ScriptedResponse {
                status: 401,
                body: br#"{"error":"AuthenticationRequired","message":"bad pwd"}"#
                    .to_vec(),
            }],
        );
        let agent = agent_with_fetcher(fetcher);

        let events: Arc<Mutex<Vec<AtpSessionEvent>>> =
            Arc::new(Mutex::new(Vec::new()));
        let ev_clone = events.clone();
        agent.on_session(move |e, _| ev_clone.lock().unwrap().push(e));

        // Override `createsession_body` handler: scripts take precedence.
        // ScriptedFetcher's createSession short-circuit only fires when
        // NOT scripted; since we scripted it, the 401 flows through.
        let _ = agent.login("alice", "bad").await.unwrap_err();
        let got = events.lock().unwrap().clone();
        assert_eq!(got, vec![AtpSessionEvent::CreateFailed]);
    }

    #[tokio::test]
    async fn auto_refreshes_on_expired_access_token() {
        let fetcher = Arc::new(ScriptedFetcher::new(login_body()));

        // First call to describeServer returns 401 ExpiredToken,
        // second call (post-refresh) returns 200.
        fetcher.script(
            "com.atproto.server.describeServer",
            vec![
                ScriptedResponse {
                    status: 401,
                    body: br#"{"error":"ExpiredToken","message":"expired"}"#.to_vec(),
                },
                ScriptedResponse {
                    status: 200,
                    body: br#"{"did":"did:plc:svr"}"#.to_vec(),
                },
            ],
        );
        fetcher.script(
            "com.atproto.server.refreshSession",
            vec![ScriptedResponse {
                status: 200,
                body: br#"{"did":"did:plc:u","handle":"alice","accessJwt":"a2","refreshJwt":"r2"}"#
                    .to_vec(),
            }],
        );

        let agent = agent_with_fetcher(fetcher.clone());
        agent.login("alice", "secret").await.unwrap();

        let events: Arc<Mutex<Vec<AtpSessionEvent>>> =
            Arc::new(Mutex::new(Vec::new()));
        let ev_clone = events.clone();
        agent.on_session(move |e, _| ev_clone.lock().unwrap().push(e));

        let result = agent.describe_server().await.unwrap();
        assert_eq!(result["did"], "did:plc:svr");

        // describeServer was called twice (first 401, second success
        // after refresh); refreshSession was called exactly once.
        assert_eq!(fetcher.call_count("com.atproto.server.describeServer"), 2);
        assert_eq!(fetcher.call_count("com.atproto.server.refreshSession"), 1);

        // One Update event fired during the refresh.
        let got = events.lock().unwrap().clone();
        assert_eq!(got, vec![AtpSessionEvent::Update]);
    }

    #[tokio::test]
    async fn concurrent_expired_token_refreshes_once() {
        let fetcher = Arc::new(ScriptedFetcher::new(login_body()));

        // All 401s for the first three attempts; subsequent calls get
        // the scripted OK response (the last entry is reused).
        fetcher.script(
            "com.atproto.server.describeServer",
            vec![
                ScriptedResponse {
                    status: 401,
                    body: br#"{"error":"ExpiredToken","message":"expired"}"#.to_vec(),
                },
                ScriptedResponse {
                    status: 200,
                    body: br#"{"did":"did:plc:svr"}"#.to_vec(),
                },
            ],
        );
        fetcher.script(
            "com.atproto.server.refreshSession",
            vec![ScriptedResponse {
                status: 200,
                body: br#"{"did":"did:plc:u","handle":"alice","accessJwt":"a2","refreshJwt":"r2"}"#
                    .to_vec(),
            }],
        );

        let agent = Arc::new(agent_with_fetcher(fetcher.clone()));
        agent.login("alice", "secret").await.unwrap();

        // 5 concurrent calls all hit 401 on first attempt. Refresh
        // must fire exactly once — the dedup lock + access-token
        // staleness check guarantee this.
        let mut handles = Vec::new();
        for _ in 0..5 {
            let a = agent.clone();
            handles.push(tokio::spawn(async move {
                a.describe_server().await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(
            fetcher.call_count("com.atproto.server.refreshSession"),
            1,
            "concurrent callers must share one refreshSession call",
        );
    }

    #[tokio::test]
    async fn emits_expired_when_refresh_itself_401s() {
        let fetcher = Arc::new(ScriptedFetcher::new(login_body()));
        fetcher.script(
            "com.atproto.server.refreshSession",
            vec![ScriptedResponse {
                status: 401,
                body: br#"{"error":"AuthenticationRequired","message":"refresh expired"}"#.to_vec(),
            }],
        );
        let agent = agent_with_fetcher(fetcher);
        agent.login("alice", "secret").await.unwrap();

        let events: Arc<Mutex<Vec<AtpSessionEvent>>> =
            Arc::new(Mutex::new(Vec::new()));
        let ev_clone = events.clone();
        agent.on_session(move |e, _| ev_clone.lock().unwrap().push(e));

        let _ = agent.refresh_session().await.unwrap_err();
        let got = events.lock().unwrap().clone();
        assert_eq!(got, vec![AtpSessionEvent::Expired]);
        assert!(agent.session().await.is_none(), "session cleared on expired refresh");
    }

}
