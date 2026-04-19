//! Adversarial tests for proto-blue-xrpc.
//!
//! Each test spins up a throwaway `tokio::net::TcpListener` on 127.0.0.1, has
//! `XrpcClient` fire a single request at it, and inspects the captured bytes.
//! This avoids pulling in a heavyweight mock-http dependency while giving us
//! wire-level visibility into how `XrpcClient` encodes paths, query params,
//! headers, and bodies — and how it parses the response.
//!
//! The checklist comes from the parity audit of `@atproto/xrpc`:
//!   * array params encode as repeated keys,
//!   * path is always `/xrpc/<nsid>`,
//!   * JSON bodies get `Content-Type: application/json`,
//!   * raw-byte bodies honor `CallOptions::encoding`,
//!   * 4xx and 5xx responses are turned into `XrpcError` with the right
//!     status enum and `error` / `message` fields extracted from JSON,
//!   * network failure (connection refused) surfaces as a non-Xrpc `Error`.

use std::collections::HashMap;
use std::sync::Arc;

use proto_blue_xrpc::{
    CallOptions, Error as XrpcClientError, HeadersMap, QueryParams, QueryValue, ResponseType,
    XrpcBody, XrpcClient,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Captured request/response round-trip from the mock server.
#[derive(Default, Debug, Clone)]
struct Captured {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// Spin up a one-shot HTTP server that replies with a canned status + body,
/// captures whatever request came in, and returns both the base URL and a
/// handle on the captured request.
///
/// This is deliberately minimal — it does not implement chunked encoding,
/// keep-alive, or HTTP/2. `XrpcClient` only needs to send a single simple
/// request per test so that's fine.
async fn spawn_oneshot_server(
    status: u16,
    resp_content_type: &'static str,
    resp_body: Vec<u8>,
) -> (String, Arc<Mutex<Option<Captured>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured: Arc<Mutex<Option<Captured>>> = Arc::new(Mutex::new(None));
    let out = captured.clone();

    tokio::spawn(async move {
        let (mut socket, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => return,
        };
        let mut buf = Vec::with_capacity(2048);
        // Read up to ~8 KiB; that's enough for every test below.
        let mut tmp = [0u8; 2048];
        // Read until we see header terminator \r\n\r\n plus any body.
        loop {
            let n = match socket.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                // Read a little more in case body is coming and hasn't
                // fully arrived. This is a best-effort: we rely on Content-
                // Length being honored.
                if let Some(cl) = extract_content_length(&buf) {
                    let headers_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                    while buf.len() < headers_end + cl {
                        let n = match socket.read(&mut tmp).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                    }
                }
                break;
            }
        }

        *out.lock().await = Some(parse_request(&buf));

        // Canned response.
        let mut resp = format!(
            "HTTP/1.1 {status} Mock\r\nContent-Type: {resp_content_type}\r\nContent-Length: {}\r\n\r\n",
            resp_body.len()
        )
        .into_bytes();
        resp.extend_from_slice(&resp_body);
        let _ = socket.write_all(&resp).await;
        let _ = socket.flush().await;
    });

    (format!("http://127.0.0.1:{port}"), captured)
}

fn extract_content_length(buf: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn parse_request(buf: &[u8]) -> Captured {
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(buf.len());
    let head = std::str::from_utf8(&buf[..split]).unwrap_or("").to_string();
    let body = if buf.len() > split + 4 {
        buf[split + 4..].to_vec()
    } else {
        Vec::new()
    };

    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    Captured {
        method,
        path,
        headers,
        body,
    }
}

// ---------------------------------------------------------------
// URL construction and path encoding.
// ---------------------------------------------------------------

#[tokio::test]
async fn query_path_uses_xrpc_prefix() {
    let (base, captured) = spawn_oneshot_server(200, "application/json", b"{}".to_vec()).await;
    let client = XrpcClient::new(&base).unwrap();
    client
        .query("com.atproto.server.describeServer", None, None)
        .await
        .unwrap();
    let c = captured.lock().await.clone().expect("request captured");
    assert_eq!(c.method, "GET");
    assert_eq!(c.path, "/xrpc/com.atproto.server.describeServer");
}

#[tokio::test]
async fn service_url_with_path_prefix_is_respected() {
    // Some proxies host the PDS under a sub-path; XrpcClient must preserve it.
    let (base, captured) = spawn_oneshot_server(200, "application/json", b"{}".to_vec()).await;
    let client = XrpcClient::new(format!("{base}/api")).unwrap();
    client.query("foo.bar.baz", None, None).await.unwrap();
    let c = captured.lock().await.clone().unwrap();
    assert_eq!(c.path, "/api/xrpc/foo.bar.baz");
}

// ---------------------------------------------------------------
// Query parameters.
// ---------------------------------------------------------------

#[tokio::test]
async fn array_params_emit_repeated_keys() {
    let (base, captured) = spawn_oneshot_server(200, "application/json", b"{}".to_vec()).await;
    let client = XrpcClient::new(&base).unwrap();

    let mut params = QueryParams::new();
    params.insert(
        "tag".into(),
        QueryValue::from(vec!["a".to_string(), "b".to_string(), "c".to_string()]),
    );
    client
        .query("app.bsky.feed.getPosts", Some(&params), None)
        .await
        .unwrap();

    let c = captured.lock().await.clone().unwrap();
    // Query string contains three `tag=` pairs in some order.
    let query = c.path.split_once('?').map(|x| x.1).unwrap_or_default();
    let pairs: Vec<&str> = query.split('&').collect();
    let mut tag_values: Vec<&str> = pairs
        .iter()
        .filter_map(|p| p.strip_prefix("tag="))
        .collect();
    tag_values.sort();
    assert_eq!(tag_values, vec!["a", "b", "c"]);
}

#[tokio::test]
async fn special_chars_in_query_value_are_percent_encoded() {
    let (base, captured) = spawn_oneshot_server(200, "application/json", b"{}".to_vec()).await;
    let client = XrpcClient::new(&base).unwrap();

    let mut params = QueryParams::new();
    // Spaces, ampersands, equals, and plus need encoding in query strings.
    params.insert("q".into(), QueryValue::String("a b&c=d+e".into()));
    client.query("foo", Some(&params), None).await.unwrap();

    let c = captured.lock().await.clone().unwrap();
    let query = c.path.split_once('?').map(|x| x.1).unwrap_or_default();
    // Must not contain raw `&` inside the value, raw `=` inside the value,
    // or raw space. Accept either `+` or `%20` for space.
    assert!(
        query.starts_with("q="),
        "expected single q= param, got {query:?}"
    );
    let value = &query["q=".len()..];
    assert!(!value.contains('&'), "ampersand must be escaped: {value:?}");
    assert!(
        !value.chars().any(|c| c == ' '),
        "raw space must be escaped: {value:?}"
    );
}

#[tokio::test]
async fn integer_and_boolean_params_serialize_flat() {
    let (base, captured) = spawn_oneshot_server(200, "application/json", b"{}".to_vec()).await;
    let client = XrpcClient::new(&base).unwrap();

    let mut params = QueryParams::new();
    params.insert("limit".into(), QueryValue::Integer(50));
    params.insert("reverse".into(), QueryValue::Boolean(true));
    client.query("foo", Some(&params), None).await.unwrap();

    let c = captured.lock().await.clone().unwrap();
    let query = c.path.split_once('?').map(|x| x.1).unwrap_or_default();
    assert!(query.contains("limit=50"), "query was {query:?}");
    assert!(query.contains("reverse=true"), "query was {query:?}");
}

// ---------------------------------------------------------------
// Body content types.
// ---------------------------------------------------------------

#[tokio::test]
async fn json_body_sets_application_json() {
    let (base, captured) = spawn_oneshot_server(200, "application/json", b"{}".to_vec()).await;
    let client = XrpcClient::new(&base).unwrap();
    client
        .procedure(
            "com.atproto.repo.createRecord",
            None,
            Some(XrpcBody::Json(serde_json::json!({"a": 1}))),
            None,
        )
        .await
        .unwrap();
    let c = captured.lock().await.clone().unwrap();
    assert_eq!(c.method, "POST");
    let ct = c.headers.get("content-type").cloned().unwrap_or_default();
    assert!(ct.starts_with("application/json"), "CT was {ct:?}");
    let body: serde_json::Value = serde_json::from_slice(&c.body).unwrap();
    assert_eq!(body["a"], 1);
}

#[tokio::test]
async fn bytes_body_uses_provided_encoding_header() {
    let (base, captured) = spawn_oneshot_server(200, "application/json", b"{}".to_vec()).await;
    let client = XrpcClient::new(&base).unwrap();
    let opts = CallOptions {
        encoding: Some("image/png".into()),
        headers: None,
        ..Default::default()
    };
    client
        .procedure(
            "com.atproto.repo.uploadBlob",
            None,
            Some(XrpcBody::Bytes(vec![0x89, 0x50, 0x4E, 0x47])),
            Some(&opts),
        )
        .await
        .unwrap();
    let c = captured.lock().await.clone().unwrap();
    assert_eq!(c.headers.get("content-type").unwrap(), "image/png");
    assert_eq!(c.body, vec![0x89, 0x50, 0x4E, 0x47]);
}

#[tokio::test]
async fn bytes_body_default_is_octet_stream() {
    let (base, captured) = spawn_oneshot_server(200, "application/json", b"{}".to_vec()).await;
    let client = XrpcClient::new(&base).unwrap();
    client
        .procedure("foo", None, Some(XrpcBody::Bytes(b"abc".to_vec())), None)
        .await
        .unwrap();
    let c = captured.lock().await.clone().unwrap();
    assert_eq!(
        c.headers.get("content-type").unwrap(),
        "application/octet-stream"
    );
}

// ---------------------------------------------------------------
// Header forwarding.
// ---------------------------------------------------------------

#[tokio::test]
async fn default_authorization_header_forwarded() {
    let (base, captured) = spawn_oneshot_server(200, "application/json", b"{}".to_vec()).await;
    let mut client = XrpcClient::new(&base).unwrap();
    client.set_header("Authorization", "Bearer token-123");
    client.query("foo", None, None).await.unwrap();
    let c = captured.lock().await.clone().unwrap();
    assert_eq!(c.headers.get("authorization").unwrap(), "Bearer token-123");
}

#[tokio::test]
async fn call_specific_header_overrides_default() {
    let (base, captured) = spawn_oneshot_server(200, "application/json", b"{}".to_vec()).await;
    let mut client = XrpcClient::new(&base).unwrap();
    client.set_header("authorization", "Bearer default");

    let mut override_headers = HeadersMap::new();
    override_headers.insert("Authorization".into(), "Bearer override".into());
    let opts = CallOptions {
        encoding: None,
        headers: Some(override_headers),
        ..Default::default()
    };
    client.query("foo", None, Some(&opts)).await.unwrap();
    let c = captured.lock().await.clone().unwrap();
    assert_eq!(c.headers.get("authorization").unwrap(), "Bearer override");
}

// ---------------------------------------------------------------
// Error response parsing.
// ---------------------------------------------------------------

#[tokio::test]
async fn json_4xx_body_produces_xrpc_error_with_fields() {
    let body = br#"{"error":"InvalidRequest","message":"bad handle"}"#.to_vec();
    let (base, _captured) = spawn_oneshot_server(400, "application/json", body).await;
    let client = XrpcClient::new(&base).unwrap();

    let err = client.query("foo", None, None).await.unwrap_err();
    match err {
        XrpcClientError::Xrpc(x) => {
            assert_eq!(x.status, ResponseType::InvalidRequest);
            assert_eq!(x.error.as_deref(), Some("InvalidRequest"));
            assert_eq!(x.message.as_deref(), Some("bad handle"));
        }
        other => panic!("expected Xrpc error, got {other:?}"),
    }
}

#[tokio::test]
async fn rate_limit_status_mapped_correctly() {
    let body = br#"{"error":"RateLimitExceeded"}"#.to_vec();
    let (base, _captured) = spawn_oneshot_server(429, "application/json", body).await;
    let client = XrpcClient::new(&base).unwrap();
    let err = client.query("foo", None, None).await.unwrap_err();
    match err {
        XrpcClientError::Xrpc(x) => {
            assert_eq!(x.status, ResponseType::RateLimitExceeded);
        }
        other => panic!("expected Xrpc error, got {other:?}"),
    }
}

#[tokio::test]
async fn unknown_5xx_status_maps_to_internal_server_error() {
    let (base, _captured) = spawn_oneshot_server(599, "application/json", b"{}".to_vec()).await;
    let client = XrpcClient::new(&base).unwrap();
    let err = client.query("foo", None, None).await.unwrap_err();
    match err {
        XrpcClientError::Xrpc(x) => {
            // The fallback for 5xx is InternalServerError.
            assert_eq!(x.status, ResponseType::InternalServerError);
        }
        other => panic!("expected Xrpc error, got {other:?}"),
    }
}

#[tokio::test]
async fn non_json_error_body_yields_xrpc_error_with_no_fields() {
    let (base, _captured) = spawn_oneshot_server(500, "text/plain", b"oops".to_vec()).await;
    let client = XrpcClient::new(&base).unwrap();
    let err = client.query("foo", None, None).await.unwrap_err();
    match err {
        XrpcClientError::Xrpc(x) => {
            assert_eq!(x.status, ResponseType::InternalServerError);
            assert!(x.error.is_none());
            assert!(x.message.is_none());
        }
        other => panic!("expected Xrpc error, got {other:?}"),
    }
}

// ---------------------------------------------------------------
// Network failure: connecting to a port that isn't listening must NOT be
// wrapped as Xrpc — it's a transport error.
// ---------------------------------------------------------------

#[tokio::test]
async fn connection_refused_is_not_an_xrpc_error() {
    // Port 1 is virtually always closed on Linux.
    let client = XrpcClient::new("http://127.0.0.1:1").unwrap();
    let err = client.query("foo", None, None).await.unwrap_err();
    match err {
        XrpcClientError::Xrpc(_) => {
            panic!("connection failure must not surface as XrpcError");
        }
        _ => { /* any non-Xrpc variant is fine */ }
    }
}

// ---------------------------------------------------------------
// Response body parsing.
// ---------------------------------------------------------------

#[tokio::test]
async fn json_success_body_is_parsed_into_data() {
    let body = br#"{"did":"did:plc:abc","handle":"alice.test"}"#.to_vec();
    let (base, _captured) = spawn_oneshot_server(200, "application/json", body).await;
    let client = XrpcClient::new(&base).unwrap();
    let resp = client.query("foo", None, None).await.unwrap();
    assert_eq!(resp.data["did"], "did:plc:abc");
    assert_eq!(resp.data["handle"], "alice.test");
}

// ---------------------------------------------------------------
// Pure ResponseType mapping (no server needed).
// ---------------------------------------------------------------

#[test]
fn response_type_from_status_covers_known_codes() {
    assert_eq!(ResponseType::from_http_status(200), ResponseType::Success);
    assert_eq!(
        ResponseType::from_http_status(400),
        ResponseType::InvalidRequest
    );
    assert_eq!(
        ResponseType::from_http_status(401),
        ResponseType::AuthenticationRequired
    );
    assert_eq!(ResponseType::from_http_status(403), ResponseType::Forbidden);
    assert_eq!(
        ResponseType::from_http_status(404),
        ResponseType::XRPCNotSupported
    );
    assert_eq!(
        ResponseType::from_http_status(429),
        ResponseType::RateLimitExceeded
    );
    assert_eq!(
        ResponseType::from_http_status(500),
        ResponseType::InternalServerError
    );
}
