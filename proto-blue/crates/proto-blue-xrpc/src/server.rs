//! XRPC server — the other half of `XrpcClient`.
//!
//! Hosts an HTTP server that routes `/xrpc/<nsid>` requests to
//! registered handlers. Mirrors the shape of `@atproto/xrpc-server`:
//!
//! - handlers registered by NSID + HTTP method (query=GET, procedure=POST),
//! - optional pluggable [`AuthVerifier`] per-method,
//! - optional pluggable [`RateLimiter`] per-method or global,
//! - standard atproto error responses (`XRPCNotSupported` for unknown
//!   NSIDs, `InvalidRequest` for malformed bodies, etc.),
//! - built on top of [`axum`] so it composes with any tower-service
//!   stack the application already uses.
//!
//! # Example
//!
//! ```no_run
//! # use proto_blue_xrpc::server::{XrpcServer, XrpcServerError};
//! # use serde_json::json;
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let server = XrpcServer::new()
//!     .query("com.atproto.server.describeServer", |_ctx| async {
//!         Ok::<_, XrpcServerError>(json!({
//!             "did": "did:plc:server",
//!             "availableUserDomains": [".example.com"],
//!         }))
//!     });
//! let app = server.into_router();
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//! axum::serve(listener, app).await?;
//! # Ok(()) }
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::{
        FromRequestParts, Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use futures::{SinkExt, Stream, StreamExt};
use serde_json::{Value as JsonValue, json};

use crate::error::ResponseType;

// ── public trait objects ────────────────────────────────────────────

/// Result type for handlers — they return either a JSON value or an
/// [`XrpcServerError`] that maps to an atproto error response.
pub type HandlerResult = Result<JsonValue, XrpcServerError>;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type HandlerFn = Arc<dyn Fn(HandlerContext) -> BoxFuture<HandlerResult> + Send + Sync>;

/// Item yielded by a subscription handler's stream. Each item is
/// wire-encoded as a DAG-CBOR message frame before being sent to the
/// client; an `Err` closes the stream after emitting one error frame.
pub type StreamItem = Result<JsonValue, XrpcServerError>;

/// A subscription handler produces a stream of [`StreamItem`]s. The
/// server pumps the stream into the client-facing WebSocket, encoding
/// each item as a message/error frame via
/// [`proto_blue_lex_cbor`] + [`proto_blue_lex_data::LexValue`].
pub type StreamHandlerFn = Arc<
    dyn Fn(HandlerContext) -> Pin<Box<dyn Stream<Item = StreamItem> + Send>>
        + Send
        + Sync,
>;

/// Context passed to every handler invocation.
///
/// Handlers deserialize `params` and `body` themselves with `serde_json`
/// as needed. That's the same deliberate design as the TS server, which
/// leaves schema-level validation to the lexicon layer rather than
/// hard-coding it into the dispatch path.
pub struct HandlerContext {
    /// The requested NSID (e.g. `"com.atproto.repo.createRecord"`).
    pub nsid: String,
    /// Query parameters, deduplicated (first occurrence wins).
    pub params: HashMap<String, String>,
    /// Raw request body; empty for GET requests.
    pub body: Bytes,
    /// Request headers passed through from axum.
    pub headers: HeaderMap,
    /// Auth result — `None` if the method didn't require auth or if no
    /// verifier was configured.
    pub auth: Option<AuthContext>,
}

impl HandlerContext {
    /// Parse the request body as JSON. Returns `Ok(None)` on empty body.
    pub fn json_body(&self) -> Result<Option<JsonValue>, XrpcServerError> {
        if self.body.is_empty() {
            return Ok(None);
        }
        serde_json::from_slice(&self.body).map(Some).map_err(|e| {
            XrpcServerError::new(ResponseType::InvalidRequest, "invalid JSON body")
                .with_error_name("InvalidRequest")
                .with_cause(e.to_string())
        })
    }
}

/// Opaque auth context produced by [`AuthVerifier::verify`].
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// DID of the authenticated principal, if the verifier identified one.
    pub did: Option<String>,
    /// Raw bearer/DPoP token for handlers that need to forward it.
    pub raw_token: Option<String>,
    /// Arbitrary key-value metadata the verifier wants to pass through.
    pub metadata: HashMap<String, String>,
}

/// Verify a request's credentials. A bad token must return `Err`; a
/// well-formed but anonymous request must return `Ok(AuthContext { did: None, .. })`.
pub trait AuthVerifier: Send + Sync {
    fn verify(&self, headers: &HeaderMap, nsid: &str) -> Result<AuthContext, XrpcServerError>;
}

/// Apply a rate-limit decision. Returning `Err(RateLimitExceeded)` short-
/// circuits the handler; returning `Ok(())` lets the request through.
pub trait RateLimiter: Send + Sync {
    fn check(&self, key: &str, headers: &HeaderMap) -> Result<(), XrpcServerError>;
}

// ── error type ──────────────────────────────────────────────────────

/// Error returned by a server-side handler or middleware.
///
/// Maps to the atproto-standard error JSON `{error, message}` at whatever
/// HTTP status [`ResponseType`] dictates.
#[derive(Debug, Clone)]
pub struct XrpcServerError {
    pub status: ResponseType,
    pub error: Option<String>,
    pub message: Option<String>,
    /// Optional developer-facing cause; logged but not returned to the
    /// client.
    pub cause: Option<String>,
}

impl XrpcServerError {
    pub fn new(status: ResponseType, message: impl Into<String>) -> Self {
        XrpcServerError {
            status,
            error: None,
            message: Some(message.into()),
            cause: None,
        }
    }

    pub fn with_error_name(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    pub fn with_cause(mut self, cause: impl Into<String>) -> Self {
        self.cause = Some(cause.into());
        self
    }
}

impl std::fmt::Display for XrpcServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.error, &self.message) {
            (Some(e), Some(m)) => write!(f, "{e}: {m}"),
            (Some(e), None) => write!(f, "{e}"),
            (None, Some(m)) => write!(f, "{m}"),
            (None, None) => write!(f, "{}", self.status),
        }
    }
}

impl std::error::Error for XrpcServerError {}

impl IntoResponse for XrpcServerError {
    fn into_response(self) -> Response {
        let status_code =
            StatusCode::from_u16(self.status as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = json!({
            "error": self.error.unwrap_or_else(|| self.status.name().to_string()),
            "message": self.message.unwrap_or_default(),
        });
        (status_code, axum::Json(body)).into_response()
    }
}

// ── server ──────────────────────────────────────────────────────────

/// Which HTTP methods a registered NSID accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodKind {
    Query,
    Procedure,
    /// WebSocket subscription (firehose-style). Served at GET
    /// `/xrpc/<nsid>` with an `Upgrade: websocket` header.
    Subscription,
}

struct MethodDef {
    kind: MethodKind,
    /// Unary handler for Query / Procedure. `None` for subscriptions.
    handler: Option<HandlerFn>,
    /// Stream handler for subscriptions. `None` for Query / Procedure.
    stream_handler: Option<StreamHandlerFn>,
    require_auth: bool,
    rate_limit_key: Option<String>,
}

/// Builder-and-router for an atproto XRPC server.
pub struct XrpcServer {
    methods: HashMap<String, MethodDef>,
    auth: Option<Arc<dyn AuthVerifier>>,
    rate_limiter: Option<Arc<dyn RateLimiter>>,
    global_rate_limit_key: Option<String>,
}

impl Default for XrpcServer {
    fn default() -> Self {
        Self::new()
    }
}

impl XrpcServer {
    pub fn new() -> Self {
        XrpcServer {
            methods: HashMap::new(),
            auth: None,
            rate_limiter: None,
            global_rate_limit_key: None,
        }
    }

    /// Register a GET handler at `/xrpc/<nsid>`.
    pub fn query<F, Fut, E>(mut self, nsid: impl Into<String>, handler: F) -> Self
    where
        F: Fn(HandlerContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<JsonValue, E>> + Send + 'static,
        E: Into<XrpcServerError> + Send + 'static,
    {
        let boxed: HandlerFn = Arc::new(move |ctx| {
            let fut = handler(ctx);
            Box::pin(async move { fut.await.map_err(Into::into) })
        });
        self.methods.insert(
            nsid.into(),
            MethodDef {
                kind: MethodKind::Query,
                handler: Some(boxed),
                stream_handler: None,
                require_auth: false,
                rate_limit_key: None,
            },
        );
        self
    }

    /// Register a POST handler at `/xrpc/<nsid>`.
    pub fn procedure<F, Fut, E>(mut self, nsid: impl Into<String>, handler: F) -> Self
    where
        F: Fn(HandlerContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<JsonValue, E>> + Send + 'static,
        E: Into<XrpcServerError> + Send + 'static,
    {
        let boxed: HandlerFn = Arc::new(move |ctx| {
            let fut = handler(ctx);
            Box::pin(async move { fut.await.map_err(Into::into) })
        });
        self.methods.insert(
            nsid.into(),
            MethodDef {
                kind: MethodKind::Procedure,
                handler: Some(boxed),
                stream_handler: None,
                require_auth: false,
                rate_limit_key: None,
            },
        );
        self
    }

    /// Register a WebSocket subscription handler at
    /// `/xrpc/<nsid>`. The handler is called on each connection and
    /// returns a stream whose items are either `Ok(JsonValue)` (sent
    /// to the client as a CBOR message frame) or `Err(XrpcServerError)`
    /// (sent as an error frame, after which the connection is closed).
    ///
    /// The handler itself is `Fn` (callable repeatedly) — one call
    /// per upgraded connection.
    pub fn stream_method<F, S>(mut self, nsid: impl Into<String>, handler: F) -> Self
    where
        F: Fn(HandlerContext) -> S + Send + Sync + 'static,
        S: Stream<Item = StreamItem> + Send + 'static,
    {
        let boxed: StreamHandlerFn = Arc::new(move |ctx| {
            let stream = handler(ctx);
            Box::pin(stream)
        });
        self.methods.insert(
            nsid.into(),
            MethodDef {
                kind: MethodKind::Subscription,
                handler: None,
                stream_handler: Some(boxed),
                require_auth: false,
                rate_limit_key: None,
            },
        );
        self
    }

    /// Require auth on a previously-registered method.
    ///
    /// No-op if `nsid` is not yet registered. Pair this with
    /// [`XrpcServer::with_auth`] to install a verifier.
    pub fn require_auth(mut self, nsid: &str) -> Self {
        if let Some(m) = self.methods.get_mut(nsid) {
            m.require_auth = true;
        }
        self
    }

    /// Attach a rate-limit key to a previously-registered method. The
    /// server passes this key to [`RateLimiter::check`] before invoking
    /// the handler.
    pub fn rate_limit(mut self, nsid: &str, key: impl Into<String>) -> Self {
        if let Some(m) = self.methods.get_mut(nsid) {
            m.rate_limit_key = Some(key.into());
        }
        self
    }

    /// Install an auth verifier used by methods with `require_auth`.
    pub fn with_auth(mut self, verifier: Arc<dyn AuthVerifier>) -> Self {
        self.auth = Some(verifier);
        self
    }

    /// Install a rate limiter. The server calls it with either a
    /// method-specific key (set via [`rate_limit`](Self::rate_limit))
    /// or with the global key (set via
    /// [`global_rate_limit_key`](Self::global_rate_limit_key)).
    pub fn with_rate_limiter(mut self, limiter: Arc<dyn RateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Set a rate-limit key applied to every request (in addition to
    /// any method-specific key).
    pub fn global_rate_limit_key(mut self, key: impl Into<String>) -> Self {
        self.global_rate_limit_key = Some(key.into());
        self
    }

    /// Compile this server configuration into an [`axum::Router`] that
    /// can be composed into a larger application or served directly.
    pub fn into_router(self) -> Router {
        let state = Arc::new(ServerState {
            methods: self.methods,
            auth: self.auth,
            rate_limiter: self.rate_limiter,
            global_rate_limit_key: self.global_rate_limit_key,
        });

        Router::new()
            // axum ≥ 0.8 uses `{name}` for path capture groups (the
            // older `:name` syntax now panics).
            //
            // GET is routed through `handle_get`, which inspects the
            // registered kind and either dispatches as a query or
            // performs the WebSocket upgrade for a subscription.
            // POST stays on the procedure path.
            .route(
                "/xrpc/{nsid}",
                get(handle_get).post(handle_procedure),
            )
            .with_state(state)
    }
}

struct ServerState {
    methods: HashMap<String, MethodDef>,
    auth: Option<Arc<dyn AuthVerifier>>,
    rate_limiter: Option<Arc<dyn RateLimiter>>,
    global_rate_limit_key: Option<String>,
}

/// GET router. When the registered NSID is a subscription, performs
/// the WebSocket upgrade; when it's a query, dispatches the unary
/// handler. When the NSID isn't registered, falls through to the
/// query dispatcher which returns a 404.
///
/// `Option<WebSocketUpgrade>` and `Bytes` can't coexist in a single
/// axum handler (Bytes consumes the body, WebSocketUpgrade needs to
/// upgrade the connection), so we serve GET without reading a body —
/// queries shouldn't carry one — and synthesise an empty `Bytes` for
/// the query dispatch.
async fn handle_get(
    State(state): State<Arc<ServerState>>,
    Path(nsid): Path<String>,
    Query(params): Query<Vec<(String, String)>>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    // Extract headers up front so we can branch on the method kind.
    let headers = req.headers().clone();

    if let Some(m) = state.methods.get(&nsid)
        && m.kind == MethodKind::Subscription
    {
        // WebSocketUpgrade is a FromRequestParts extractor; call it
        // manually so we can produce a clear "subscription requires
        // WebSocket upgrade" error rather than axum's default 400.
        let (mut parts, _body) = req.into_parts();
        let upgrade =
            match <WebSocketUpgrade as FromRequestParts<()>>::from_request_parts(&mut parts, &()).await {
                Ok(u) => u,
                Err(_) => {
                    return XrpcServerError::new(
                        ResponseType::InvalidRequest,
                        "subscription requires WebSocket upgrade",
                    )
                    .with_error_name("InvalidRequest")
                    .into_response();
                }
            };
        return subscription_upgrade(state, nsid, params, headers, upgrade);
    }
    dispatch(state, MethodKind::Query, nsid, params, headers, Bytes::new()).await
}

async fn handle_procedure(
    State(state): State<Arc<ServerState>>,
    Path(nsid): Path<String>,
    Query(params): Query<Vec<(String, String)>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    dispatch(state, MethodKind::Procedure, nsid, params, headers, body).await
}

async fn dispatch(
    state: Arc<ServerState>,
    kind: MethodKind,
    nsid: String,
    raw_params: Vec<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let method = match state.methods.get(&nsid) {
        Some(m) => m,
        None => {
            return XrpcServerError::new(
                ResponseType::XRPCNotSupported,
                format!("method {nsid} not found"),
            )
            .with_error_name("XRPCNotSupported")
            .into_response();
        }
    };
    if method.kind != kind {
        let expected = match method.kind {
            MethodKind::Query => "GET",
            MethodKind::Procedure => "POST",
            MethodKind::Subscription => "GET (WebSocket)",
        };
        // Use 405 (HTTP Method Not Allowed). atproto's spec doesn't
        // model this explicitly, so we surface it as InvalidRequest with
        // a pointer toward the correct verb.
        return XrpcServerError::new(
            ResponseType::InvalidRequest,
            format!("method {nsid} expects HTTP {expected}"),
        )
        .with_error_name("InvalidRequest")
        .into_response();
    }

    // Rate-limit check. Global first, then method-specific.
    if let Some(limiter) = &state.rate_limiter {
        if let Some(global_key) = &state.global_rate_limit_key {
            if let Err(e) = limiter.check(global_key, &headers) {
                return e.into_response();
            }
        }
        if let Some(method_key) = &method.rate_limit_key {
            if let Err(e) = limiter.check(method_key, &headers) {
                return e.into_response();
            }
        }
    }

    // Auth check.
    let auth = if method.require_auth {
        let verifier = match &state.auth {
            Some(v) => v,
            None => {
                return XrpcServerError::new(
                    ResponseType::InternalServerError,
                    "auth required but no verifier installed",
                )
                .into_response();
            }
        };
        match verifier.verify(&headers, &nsid) {
            Ok(ctx) => Some(ctx),
            Err(e) => return e.into_response(),
        }
    } else {
        None
    };

    let mut params = HashMap::new();
    for (k, v) in raw_params {
        params.entry(k).or_insert(v);
    }

    let ctx = HandlerContext {
        nsid: nsid.clone(),
        params,
        body,
        headers,
        auth,
    };

    // Unary kinds (Query / Procedure) always have `handler`;
    // Subscription never reaches this path (its dispatch lives in
    // `subscription_upgrade`). Unwrap is unreachable in practice.
    let handler = match &method.handler {
        Some(h) => h,
        None => {
            return XrpcServerError::new(
                ResponseType::InternalServerError,
                "internal: unary handler missing for non-subscription method",
            )
            .into_response();
        }
    };

    match handler(ctx).await {
        Ok(value) => axum::Json(value).into_response(),
        Err(e) => e.into_response(),
    }
}

// ── Subscription upgrade + pump ──────────────────────────────────────

/// DAG-CBOR op codes for subscription frames. Kept inline here so the
/// server crate doesn't depend on `proto-blue-ws` — the values are
/// fixed by the atproto spec.
const OP_MESSAGE: i64 = 1;
const OP_ERROR: i64 = -1;

/// Perform the WebSocket upgrade for a subscription method and spawn
/// the pump that drives the handler's stream into frame-encoded
/// messages.
fn subscription_upgrade(
    state: Arc<ServerState>,
    nsid: String,
    raw_params: Vec<(String, String)>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    // Build the handler context once so we can move it into the
    // upgrade closure. Query params are deduplicated (first-wins) to
    // match query/procedure behaviour.
    let mut params: HashMap<String, String> = HashMap::new();
    for (k, v) in raw_params {
        params.entry(k).or_insert(v);
    }
    let ctx = HandlerContext {
        nsid: nsid.clone(),
        params,
        body: Bytes::new(),
        headers,
        auth: None,
    };

    // Look up + clone the stream handler up front so the move-into
    // closure is cheap and panic-free even if state mutates later.
    let stream_handler = match state.methods.get(&nsid).and_then(|m| m.stream_handler.as_ref()) {
        Some(h) => h.clone(),
        None => {
            return XrpcServerError::new(
                ResponseType::InternalServerError,
                "internal: subscription handler missing",
            )
            .into_response();
        }
    };

    upgrade.on_upgrade(move |socket| async move {
        run_subscription_pump(socket, stream_handler, ctx).await;
    })
}

/// Drive the handler's stream into the client-facing WebSocket. Each
/// `Ok(json)` item is encoded as a DAG-CBOR message frame; each
/// `Err(e)` as an error frame followed by a clean close.
///
/// Exits promptly if the peer disconnects (the WebSocket's own
/// read-half receives a `Close` / `None`).
async fn run_subscription_pump(
    socket: WebSocket,
    handler: StreamHandlerFn,
    ctx: HandlerContext,
) {
    let (mut sink, mut client_read) = socket.split();
    let mut stream = handler(ctx);

    loop {
        tokio::select! {
            // Peer disconnect / close frame: stop pumping immediately.
            incoming = client_read.next() => {
                match incoming {
                    None => break,
                    Some(Err(_)) => break,
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(_)) => {
                        // Peers may send pings / pongs / text; axum
                        // handles pings automatically. We ignore other
                        // inbound messages — subscription streams are
                        // one-way at this layer.
                        continue;
                    }
                }
            }
            // Next handler item.
            item = stream.next() => {
                match item {
                    Some(Ok(value)) => {
                        match encode_message_frame(&value) {
                            Ok(bytes) => {
                                if sink.send(Message::Binary(bytes.into())).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                let _ = send_error_frame(&mut sink, &e).await;
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        let _ = send_error_frame(&mut sink, &e).await;
                        break;
                    }
                    None => {
                        // Handler exhausted its stream — clean close.
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
        }
    }
}

/// Encode a JSON value as a DAG-CBOR message frame (two back-to-back
/// CBOR values: header `{op:1}` + body).
fn encode_message_frame(value: &JsonValue) -> Result<Vec<u8>, XrpcServerError> {
    use proto_blue_lex_data::LexValue;

    // Convert the handler-produced JSON into a LexValue (leniently —
    // we trust our own handler output).
    let body = proto_blue_lex_json::json_to_lex(value);
    let mut header = std::collections::BTreeMap::new();
    header.insert(
        "op".to_string(),
        LexValue::Integer(OP_MESSAGE),
    );
    let header = LexValue::Map(header);

    let mut bytes = proto_blue_lex_cbor::encode(&header).map_err(|e| {
        XrpcServerError::new(
            ResponseType::InternalServerError,
            format!("frame header encode: {e}"),
        )
    })?;
    let body_bytes = proto_blue_lex_cbor::encode(&body).map_err(|e| {
        XrpcServerError::new(
            ResponseType::InternalServerError,
            format!("frame body encode: {e}"),
        )
    })?;
    bytes.extend_from_slice(&body_bytes);
    Ok(bytes)
}

/// Send an error frame (header op=-1 + `{error, message}` body) then
/// a Close frame. Best-effort — if either write fails the pump just
/// exits.
async fn send_error_frame(
    sink: &mut futures::stream::SplitSink<WebSocket, Message>,
    err: &XrpcServerError,
) -> Result<(), ()> {
    use proto_blue_lex_data::LexValue;

    let mut header = std::collections::BTreeMap::new();
    header.insert(
        "op".to_string(),
        LexValue::Integer(OP_ERROR),
    );
    let header = LexValue::Map(header);

    let mut body_map = std::collections::BTreeMap::new();
    body_map.insert(
        "error".to_string(),
        LexValue::String(err.error.clone().unwrap_or_else(|| "Unknown".into())),
    );
    if let Some(msg) = &err.message {
        body_map.insert("message".to_string(), LexValue::String(msg.clone()));
    }
    let body = LexValue::Map(body_map);

    let mut bytes = proto_blue_lex_cbor::encode(&header).map_err(|_| ())?;
    let body_bytes = proto_blue_lex_cbor::encode(&body).map_err(|_| ())?;
    bytes.extend_from_slice(&body_bytes);

    sink.send(Message::Binary(bytes.into())).await.map_err(|_| ())?;
    sink.send(Message::Close(None)).await.map_err(|_| ())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use axum::{Router, body::Body};
    use tower::ServiceExt;

    fn app() -> Router {
        XrpcServer::new()
            .query("com.atproto.server.describeServer", |_ctx| async move {
                Ok::<_, XrpcServerError>(json!({ "did": "did:plc:server" }))
            })
            .procedure("com.atproto.repo.createRecord", |ctx| async move {
                let body = ctx.json_body()?.ok_or_else(|| {
                    XrpcServerError::new(ResponseType::InvalidRequest, "body required")
                })?;
                Ok::<_, XrpcServerError>(json!({ "uri": body["collection"], "cid": "bafy123" }))
            })
            .into_router()
    }

    async fn read_body_json(resp: Response) -> (StatusCode, JsonValue) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: JsonValue = serde_json::from_slice(&bytes).unwrap_or(JsonValue::Null);
        (status, value)
    }

    // ── routing + method dispatch ──

    #[tokio::test]
    async fn query_returns_handler_json() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.atproto.server.describeServer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, body) = read_body_json(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["did"], "did:plc:server");
    }

    #[tokio::test]
    async fn procedure_receives_body_and_returns_json() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.createRecord")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({ "collection": "at://foo" })).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, body) = read_body_json(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["uri"], "at://foo");
        assert_eq!(body["cid"], "bafy123");
    }

    #[tokio::test]
    async fn unknown_nsid_returns_xrpc_not_supported() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.does.not.exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, body) = read_body_json(resp).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "XRPCNotSupported");
    }

    #[tokio::test]
    async fn wrong_http_method_is_rejected() {
        // describeServer is a query (GET); POST must be rejected.
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.server.describeServer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, body) = read_body_json(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["message"].as_str().unwrap().contains("GET"));
    }

    #[tokio::test]
    async fn malformed_json_body_returns_invalid_request() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.createRecord")
                    .header("content-type", "application/json")
                    .body(Body::from("{ not json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, body) = read_body_json(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "InvalidRequest");
    }

    #[tokio::test]
    async fn handler_error_propagates_with_correct_status() {
        let router = XrpcServer::new()
            .query("test.fails", |_ctx| async move {
                Err::<JsonValue, _>(
                    XrpcServerError::new(ResponseType::Forbidden, "no access")
                        .with_error_name("Forbidden"),
                )
            })
            .into_router();

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/xrpc/test.fails")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, body) = read_body_json(resp).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "Forbidden");
        assert_eq!(body["message"], "no access");
    }

    // ── auth ──

    struct AlwaysAllow {
        did: String,
    }
    impl AuthVerifier for AlwaysAllow {
        fn verify(
            &self,
            _headers: &HeaderMap,
            _nsid: &str,
        ) -> Result<AuthContext, XrpcServerError> {
            Ok(AuthContext {
                did: Some(self.did.clone()),
                raw_token: None,
                metadata: HashMap::new(),
            })
        }
    }
    struct AlwaysDeny;
    impl AuthVerifier for AlwaysDeny {
        fn verify(
            &self,
            _headers: &HeaderMap,
            _nsid: &str,
        ) -> Result<AuthContext, XrpcServerError> {
            Err(
                XrpcServerError::new(ResponseType::AuthenticationRequired, "bad token")
                    .with_error_name("AuthenticationRequired"),
            )
        }
    }

    #[tokio::test]
    async fn protected_method_forwards_auth_did_to_handler() {
        let router = XrpcServer::new()
            .query("test.me", |ctx| async move {
                let did = ctx
                    .auth
                    .as_ref()
                    .and_then(|a| a.did.clone())
                    .unwrap_or_default();
                Ok::<_, XrpcServerError>(json!({ "did": did }))
            })
            .require_auth("test.me")
            .with_auth(Arc::new(AlwaysAllow {
                did: "did:plc:auth".into(),
            }))
            .into_router();

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/xrpc/test.me")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, body) = read_body_json(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["did"], "did:plc:auth");
    }

    #[tokio::test]
    async fn protected_method_rejects_bad_auth() {
        let router = XrpcServer::new()
            .query("test.me", |_ctx| async move {
                Ok::<_, XrpcServerError>(json!({}))
            })
            .require_auth("test.me")
            .with_auth(Arc::new(AlwaysDeny))
            .into_router();

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/xrpc/test.me")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, body) = read_body_json(resp).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "AuthenticationRequired");
    }

    #[tokio::test]
    async fn unprotected_method_ignores_auth_verifier() {
        let router = XrpcServer::new()
            .query("test.public", |ctx| async move {
                assert!(ctx.auth.is_none());
                Ok::<_, XrpcServerError>(json!({ "ok": true }))
            })
            .with_auth(Arc::new(AlwaysDeny)) // would fail if consulted
            .into_router();

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/xrpc/test.public")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, _body) = read_body_json(resp).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_method_without_verifier_is_a_server_error() {
        let router = XrpcServer::new()
            .query("test.me", |_ctx| async move {
                Ok::<_, XrpcServerError>(json!({}))
            })
            .require_auth("test.me")
            .into_router();

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/xrpc/test.me")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, _) = read_body_json(resp).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ── rate limiting ──

    struct CountingLimiter {
        allowed: std::sync::atomic::AtomicUsize,
    }
    impl CountingLimiter {
        fn with_allowance(n: usize) -> Self {
            CountingLimiter {
                allowed: std::sync::atomic::AtomicUsize::new(n),
            }
        }
    }
    impl RateLimiter for CountingLimiter {
        fn check(&self, _key: &str, _headers: &HeaderMap) -> Result<(), XrpcServerError> {
            use std::sync::atomic::Ordering;
            let prev = self.allowed.fetch_sub(1, Ordering::SeqCst);
            if prev == 0 {
                Err(
                    XrpcServerError::new(ResponseType::RateLimitExceeded, "slow down")
                        .with_error_name("RateLimitExceeded"),
                )
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn rate_limiter_blocks_after_allowance() {
        let limiter = Arc::new(CountingLimiter::with_allowance(2));
        let router = XrpcServer::new()
            .query("test.limited", |_ctx| async move {
                Ok::<_, XrpcServerError>(json!({ "ok": true }))
            })
            .rate_limit("test.limited", "per-method")
            .with_rate_limiter(limiter)
            .into_router();

        for expected in [
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            let resp = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/xrpc/test.limited")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), expected);
        }
    }

    // ── params ──

    #[tokio::test]
    async fn query_params_reach_handler() {
        let router = XrpcServer::new()
            .query("test.echo", |ctx| async move {
                Ok::<_, XrpcServerError>(json!({ "params": ctx.params }))
            })
            .into_router();

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/xrpc/test.echo?limit=50&reverse=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, body) = read_body_json(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["params"]["limit"], "50");
        assert_eq!(body["params"]["reverse"], "true");
    }

    // ── XrpcServerError conversions ──

    #[tokio::test]
    async fn json_body_parse_error_maps_to_invalid_request() {
        let ctx = HandlerContext {
            nsid: "x".into(),
            params: HashMap::new(),
            body: Bytes::from_static(b"{not json"),
            headers: HeaderMap::new(),
            auth: None,
        };
        let err = ctx.json_body().unwrap_err();
        assert_eq!(err.status, ResponseType::InvalidRequest);
    }

    #[tokio::test]
    async fn empty_body_json_parse_returns_none() {
        let ctx = HandlerContext {
            nsid: "x".into(),
            params: HashMap::new(),
            body: Bytes::new(),
            headers: HeaderMap::new(),
            auth: None,
        };
        assert!(ctx.json_body().unwrap().is_none());
    }
}
