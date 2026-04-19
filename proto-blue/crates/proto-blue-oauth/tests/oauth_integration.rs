//! End-to-end integration tests for `proto-blue-oauth`.
//!
//! Covers three issues in one binary so the shared helpers in
//! `tests/common/mock_server.rs` are all exercised:
//!
//! - **#7** — `OAuthClient::fetch_client_metadata`.
//! - **#6** — Pushed Authorization Request handling in `authorize`.
//! - **#4** — Token exchange, refresh, and revocation flows.
//!
//! Every test stands up a one-shot or sequenced mock HTTP server on
//! 127.0.0.1 and asserts on the wire-level request the client emits
//! (headers, path, form fields, DPoP proof) and on how the client
//! interprets the response (success, nonce rotation, error mapping).

mod common;

use common::mock_server::{Captured, Reply, parse_form, spawn_oneshot, spawn_sequence};
use proto_blue_oauth::{
    DpopKey, DpopNonceCache, OAuthClient, OAuthClientMetadata, OAuthError, OAuthServerMetadata,
    OAuthSession, TokenSet,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ── common fixtures ─────────────────────────────────────────────────

fn client_metadata_with_id(client_id: &str) -> OAuthClientMetadata {
    OAuthClientMetadata {
        client_id: client_id.to_string(),
        redirect_uris: vec!["https://app.example.com/callback".into()],
        response_types: Some(vec!["code".into()]),
        grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
        scope: Some("atproto".into()),
        token_endpoint_auth_method: Some("none".into()),
        token_endpoint_auth_signing_alg: None,
        application_type: Some("web".into()),
        dpop_bound_access_tokens: Some(true),
        client_name: Some("Test App".into()),
        client_uri: None,
        logo_uri: None,
    }
}

fn server_metadata(
    issuer: &str,
    authorization_endpoint: &str,
    token_endpoint: &str,
    par_endpoint: Option<&str>,
    revocation_endpoint: Option<&str>,
) -> OAuthServerMetadata {
    OAuthServerMetadata {
        issuer: issuer.to_string(),
        authorization_endpoint: authorization_endpoint.to_string(),
        token_endpoint: token_endpoint.to_string(),
        jwks_uri: None,
        revocation_endpoint: revocation_endpoint.map(str::to_string),
        introspection_endpoint: None,
        pushed_authorization_request_endpoint: par_endpoint.map(str::to_string),
        require_pushed_authorization_requests: None,
        token_endpoint_auth_methods_supported: None,
        token_endpoint_auth_signing_alg_values_supported: None,
        dpop_signing_alg_values_supported: Some(vec!["ES256".into(), "ES256K".into()]),
        code_challenge_methods_supported: Some(vec!["S256".into()]),
        response_types_supported: Some(vec!["code".into()]),
        grant_types_supported: Some(vec!["authorization_code".into(), "refresh_token".into()]),
        scopes_supported: Some(vec!["atproto".into()]),
        authorization_response_iss_parameter_supported: None,
        protected_resources: None,
        client_id_metadata_document_supported: None,
    }
}

/// The canonical metadata-document JSON the tests serve. Built by
/// round-tripping an `OAuthClientMetadata` instance so the bytes are
/// always consistent with the struct.
fn metadata_json(client_id: &str) -> String {
    serde_json::to_string(&client_metadata_with_id(client_id)).unwrap()
}

/// Bind a TCP port, then build a self-referential metadata document
/// (whose `client_id` equals the URL the server responds on) and serve
/// it exactly once. Also capture the request headers so tests can
/// assert on them.
async fn spawn_metadata_server() -> (String, std::sync::Arc<tokio::sync::Mutex<Option<Captured>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}/client-metadata.json");
    let body = metadata_json(&url).into_bytes();
    let captured: std::sync::Arc<tokio::sync::Mutex<Option<Captured>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(None));
    let cap_clone = captured.clone();

    tokio::spawn(async move {
        let (mut socket, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => return,
        };
        let mut tmp = [0u8; 4096];
        let mut buf = Vec::new();
        loop {
            match socket.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        // Minimal request parse for the helper-file's benefit.
        let text = String::from_utf8_lossy(&buf).to_string();
        let mut lines = text.lines();
        let first = lines.next().unwrap_or("").to_string();
        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        let mut headers = std::collections::HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
        *cap_clone.lock().await = Some(Captured {
            method,
            path,
            headers,
            body: Vec::new(),
        });

        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = socket.write_all(head.as_bytes()).await;
        let _ = socket.write_all(&body).await;
        let _ = socket.flush().await;
    });

    (url, captured)
}

fn empty_client() -> OAuthClient {
    OAuthClient::new(client_metadata_with_id(
        "https://placeholder.example/metadata.json",
    ))
}

fn real_client(client_id: &str) -> OAuthClient {
    OAuthClient::new(client_metadata_with_id(client_id))
}

// ─────────────────────────────────────────────────────────────────────
// #7 — fetch_client_metadata
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn metadata_happy_path() {
    let (url, cap) = spawn_metadata_server().await;
    let got = empty_client().fetch_client_metadata(&url).await.unwrap();
    assert_eq!(got.client_id, url);
    assert_eq!(got.scope.as_deref(), Some("atproto"));

    // Issue #7 acceptance: must send Accept: application/json.
    let headers = cap.lock().await.clone().unwrap().headers;
    assert!(
        headers
            .get("accept")
            .map(|v| v.contains("application/json"))
            .unwrap_or(false),
        "expected Accept: application/json in headers: {headers:?}"
    );
}

#[tokio::test]
async fn metadata_rejects_non_json_content_type() {
    let (base, _) = spawn_oneshot(Reply::text(
        200,
        metadata_json("https://wont-match.example/metadata.json"),
    ))
    .await;
    let err = empty_client()
        .fetch_client_metadata(&format!("{base}/client-metadata.json"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("application/json"), "{err}");
}

#[tokio::test]
async fn metadata_accepts_json_with_charset_param() {
    // Application/json with a charset parameter is legal per RFC 8259.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}/client-metadata.json");
    let body = metadata_json(&url).into_bytes();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut tmp = [0u8; 4096];
        let mut buf = Vec::new();
        loop {
            match socket.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = socket.write_all(head.as_bytes()).await;
        let _ = socket.write_all(&body).await;
        let _ = socket.flush().await;
    });

    let got = empty_client().fetch_client_metadata(&url).await.unwrap();
    assert_eq!(got.client_id, url);
}

#[tokio::test]
async fn metadata_rejects_client_id_mismatch() {
    let (base, _) = spawn_oneshot(Reply::json(
        200,
        metadata_json("https://someone-else.example/metadata.json"),
    ))
    .await;
    let err = empty_client()
        .fetch_client_metadata(&format!("{base}/client-metadata.json"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("mismatch"), "{err}");
}

#[tokio::test]
async fn metadata_rejects_http_error_status() {
    let (base, _) = spawn_oneshot(Reply::json(404, br#"{"error":"not found"}"#.to_vec())).await;
    let err = empty_client()
        .fetch_client_metadata(&format!("{base}/client-metadata.json"))
        .await
        .unwrap_err();
    assert!(!err.to_string().is_empty());
}

#[tokio::test]
async fn metadata_rejects_malformed_json() {
    let (base, _) = spawn_oneshot(Reply::json(200, b"{ not json".to_vec())).await;
    let err = empty_client()
        .fetch_client_metadata(&format!("{base}/client-metadata.json"))
        .await
        .unwrap_err();
    assert!(!err.to_string().is_empty());
}

// ─────────────────────────────────────────────────────────────────────
// #6 — Pushed Authorization Request (PAR)
// ─────────────────────────────────────────────────────────────────────

/// Without a PAR endpoint in server metadata, `authorize` must fall back
/// to putting all parameters directly into the authorization URL.
#[tokio::test]
async fn authorize_without_par_builds_direct_url() {
    let client = real_client("https://app.example.com/metadata.json");
    let meta = server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        "https://as.example.com/token",
        None, // no PAR endpoint
        None,
    );
    let (url, _state) = client.authorize(&meta).await.unwrap();
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let has = |name: &str| pairs.iter().any(|(k, _)| k == name);
    assert!(has("response_type"));
    assert!(has("client_id"));
    assert!(has("code_challenge"));
    assert!(has("code_challenge_method"));
    assert!(has("state"));
    assert!(has("redirect_uri"));
    assert!(has("scope"));
    // No PAR -> must not have request_uri on the URL.
    assert!(!has("request_uri"));
}

/// With a PAR endpoint, `authorize` must (1) POST to it with a DPoP
/// header and form-encoded auth params, (2) receive the `request_uri`
/// in the JSON response, and (3) emit an authorization URL carrying
/// only `request_uri` and `client_id`. This is the whole acceptance
/// criterion for issue #6.
#[tokio::test]
async fn authorize_with_par_posts_and_uses_request_uri() {
    let par_reply = Reply::json(
        201,
        br#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc123","expires_in":90}"#.to_vec(),
    );
    let (par_base, cap) = spawn_oneshot(par_reply).await;
    let par_endpoint = format!("{par_base}/par");

    let client = real_client("https://app.example.com/metadata.json");
    let meta = server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        "https://as.example.com/token",
        Some(&par_endpoint),
        None,
    );
    let (url, _state) = client.authorize(&meta).await.unwrap();

    // The returned URL must be the authorization endpoint with just
    // `request_uri` and `client_id`.
    assert!(url.as_str().starts_with("https://as.example.com/authorize"));
    let pairs: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        pairs.get("request_uri").map(String::as_str),
        Some("urn:ietf:params:oauth:request_uri:abc123")
    );
    assert_eq!(
        pairs.get("client_id").map(String::as_str),
        Some("https://app.example.com/metadata.json")
    );

    // Inspect the PAR request on the wire.
    let req = cap.lock().await.clone().expect("PAR request captured");
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/par");
    let dpop = req.headers.get("dpop").cloned().unwrap_or_default();
    assert!(!dpop.is_empty(), "DPoP header missing on PAR request");
    let ct = req.headers.get("content-type").cloned().unwrap_or_default();
    assert!(
        ct.contains("application/x-www-form-urlencoded"),
        "PAR form content-type, got {ct:?}"
    );
    let form = parse_form(&req.body);
    assert_eq!(form.get("response_type").map(String::as_str), Some("code"));
    assert!(form.contains_key("code_challenge"));
    assert_eq!(
        form.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    assert!(form.contains_key("state"));
    assert_eq!(
        form.get("client_id").map(String::as_str),
        Some("https://app.example.com/metadata.json")
    );
}

/// RFC 9449 §8: if the PAR endpoint responds 400 with a `DPoP-Nonce`
/// header, the client must retry with that nonce embedded in the DPoP
/// proof. A follow-up success must be accepted and the nonce cached.
#[tokio::test]
async fn authorize_with_par_retries_on_nonce_challenge() {
    let challenge = Reply::json(400, br#"{"error":"use_dpop_nonce"}"#.to_vec())
        .with_header("DPoP-Nonce", "srv-nonce-xyz");
    let success = Reply::json(
        201,
        br#"{"request_uri":"urn:ietf:params:oauth:request_uri:ok","expires_in":90}"#.to_vec(),
    );
    let (par_base, caps) = spawn_sequence(vec![challenge, success]).await;
    let par_endpoint = format!("{par_base}/par");

    let client = real_client("https://app.example.com/metadata.json");
    let meta = server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        "https://as.example.com/token",
        Some(&par_endpoint),
        None,
    );
    let (url, _state) = client.authorize(&meta).await.unwrap();
    let pairs: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        pairs.get("request_uri").map(String::as_str),
        Some("urn:ietf:params:oauth:request_uri:ok")
    );

    // Exactly two requests were sent.
    let captured = caps.lock().await.clone();
    assert_eq!(
        captured.len(),
        2,
        "expected 2 PAR requests (challenge + retry)"
    );
    // Both should carry a DPoP header; the second must differ from the
    // first because the nonce is baked into the proof.
    let dpop1 = captured[0].headers.get("dpop").cloned().unwrap_or_default();
    let dpop2 = captured[1].headers.get("dpop").cloned().unwrap_or_default();
    assert!(!dpop1.is_empty() && !dpop2.is_empty());
    assert_ne!(dpop1, dpop2, "retry must use a fresh proof with the nonce");
}

// ─────────────────────────────────────────────────────────────────────
// #4 — Token exchange, refresh, revocation
// ─────────────────────────────────────────────────────────────────────

fn token_success_body() -> Vec<u8> {
    br#"{
      "access_token":"at-123",
      "token_type":"DPoP",
      "refresh_token":"rt-456",
      "expires_in":3600,
      "scope":"atproto",
      "sub":"did:plc:abc"
    }"#
    .to_vec()
}

fn fresh_auth_state(issuer: &str) -> proto_blue_oauth::AuthState {
    use proto_blue_oauth::AuthState;
    let dpop = DpopKey::generate().unwrap();
    AuthState {
        issuer: issuer.to_string(),
        verifier: "fake-verifier-token-for-test-only".to_string(),
        dpop_key: dpop.private_jwk,
        app_state: Some("app-state-123".to_string()),
    }
}

/// The authorization-code-for-token exchange must:
/// - POST to the token endpoint,
/// - include a `DPoP` proof header,
/// - send `grant_type=authorization_code` with `code`, `code_verifier`,
///   `redirect_uri`, and `client_id` in the form body,
/// - parse the `access_token`, `refresh_token`, `sub`, etc. back into
///   a `TokenSet`.
#[tokio::test]
async fn token_exchange_posts_correct_form_and_parses_response() {
    let (token_base, cap) = spawn_oneshot(Reply::json(200, token_success_body())).await;
    let token_endpoint = format!("{token_base}/token");

    let client = real_client("https://app.example.com/metadata.json");
    let meta = server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        &token_endpoint,
        None,
        None,
    );
    let state = fresh_auth_state("https://as.example.com");

    let token_set = client.callback("code-abc", &state, &meta).await.unwrap();
    assert_eq!(token_set.access_token, "at-123");
    assert_eq!(token_set.refresh_token.as_deref(), Some("rt-456"));
    assert_eq!(token_set.sub, "did:plc:abc");
    assert_eq!(token_set.scope, "atproto");

    let req = cap.lock().await.clone().unwrap();
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/token");
    assert!(
        !req.headers
            .get("dpop")
            .cloned()
            .unwrap_or_default()
            .is_empty(),
        "DPoP header required on token exchange"
    );
    let form = parse_form(&req.body);
    assert_eq!(
        form.get("grant_type").map(String::as_str),
        Some("authorization_code")
    );
    assert_eq!(form.get("code").map(String::as_str), Some("code-abc"));
    assert_eq!(
        form.get("code_verifier").map(String::as_str),
        Some("fake-verifier-token-for-test-only")
    );
    assert_eq!(
        form.get("redirect_uri").map(String::as_str),
        Some("https://app.example.com/callback")
    );
    assert_eq!(
        form.get("client_id").map(String::as_str),
        Some("https://app.example.com/metadata.json")
    );
}

/// OAuth error responses must propagate as `OAuthError::ServerError`
/// carrying the `error` code and `error_description` for the caller to
/// inspect.
#[tokio::test]
async fn token_exchange_surfaces_server_errors() {
    let (token_base, _cap) = spawn_oneshot(Reply::json(
        400,
        br#"{"error":"invalid_grant","error_description":"code expired"}"#.to_vec(),
    ))
    .await;
    let token_endpoint = format!("{token_base}/token");

    let client = real_client("https://app.example.com/metadata.json");
    let meta = server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        &token_endpoint,
        None,
        None,
    );
    let state = fresh_auth_state("https://as.example.com");
    let err = client
        .callback("bad-code", &state, &meta)
        .await
        .unwrap_err();
    match err {
        OAuthError::ServerError {
            error,
            error_description,
        } => {
            assert_eq!(error, "invalid_grant");
            assert_eq!(error_description, "code expired");
        }
        other => panic!("expected ServerError, got {other:?}"),
    }
}

/// Refresh-token flow:
/// - POST with `grant_type=refresh_token` + `refresh_token` field,
/// - DPoP proof present,
/// - new TokenSet returned.
#[tokio::test]
async fn refresh_token_posts_correct_form_and_updates_set() {
    let (token_base, cap) = spawn_oneshot(Reply::json(
        200,
        br#"{
          "access_token":"at-new",
          "token_type":"DPoP",
          "refresh_token":"rt-new",
          "expires_in":3600,
          "scope":"atproto",
          "sub":"did:plc:abc"
        }"#
        .to_vec(),
    ))
    .await;
    let token_endpoint = format!("{token_base}/token");

    let client = real_client("https://app.example.com/metadata.json");
    let meta = server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        &token_endpoint,
        None,
        None,
    );

    let dpop = DpopKey::generate().unwrap();
    let current = TokenSet {
        issuer: "https://as.example.com".to_string(),
        sub: "did:plc:abc".to_string(),
        scope: "atproto".to_string(),
        access_token: "at-old".to_string(),
        refresh_token: Some("rt-old".to_string()),
        token_type: "DPoP".to_string(),
        expires_at: Some("2099-01-01T00:00:00Z".to_string()),
        aud: None,
    };

    let updated = client.refresh_token(&meta, &current, &dpop).await.unwrap();
    assert_eq!(updated.access_token, "at-new");
    assert_eq!(updated.refresh_token.as_deref(), Some("rt-new"));

    let req = cap.lock().await.clone().unwrap();
    assert_eq!(req.method, "POST");
    assert!(
        !req.headers
            .get("dpop")
            .cloned()
            .unwrap_or_default()
            .is_empty(),
        "DPoP proof required on refresh"
    );
    let form = parse_form(&req.body);
    assert_eq!(
        form.get("grant_type").map(String::as_str),
        Some("refresh_token")
    );
    assert_eq!(
        form.get("refresh_token").map(String::as_str),
        Some("rt-old")
    );
    assert_eq!(
        form.get("client_id").map(String::as_str),
        Some("https://app.example.com/metadata.json")
    );
}

/// Missing refresh token must fail fast, not attempt any HTTP call.
#[tokio::test]
async fn refresh_token_without_refresh_errors_without_request() {
    let (token_base, cap) = spawn_oneshot(Reply::json(200, token_success_body())).await;
    let token_endpoint = format!("{token_base}/token");

    let client = real_client("https://app.example.com/metadata.json");
    let meta = server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        &token_endpoint,
        None,
        None,
    );
    let dpop = DpopKey::generate().unwrap();
    let current = TokenSet {
        issuer: "https://as.example.com".to_string(),
        sub: "did:plc:abc".to_string(),
        scope: "atproto".to_string(),
        access_token: "at-old".to_string(),
        refresh_token: None,
        token_type: "DPoP".to_string(),
        expires_at: None,
        aud: None,
    };

    let err = client
        .refresh_token(&meta, &current, &dpop)
        .await
        .unwrap_err();
    assert!(matches!(err, OAuthError::RefreshFailed(_)));
    // Crucially, no request was sent.
    assert!(
        cap.lock().await.is_none(),
        "no request should have been made"
    );
}

/// Revocation flow: POST to the revocation endpoint with `token` and
/// `client_id` in the form body. Success = 200.
#[tokio::test]
async fn revoke_posts_to_revocation_endpoint() {
    let (rev_base, cap) = spawn_oneshot(Reply::json(200, Vec::new())).await;
    let rev_endpoint = format!("{rev_base}/revoke");

    let client = real_client("https://app.example.com/metadata.json");
    let meta = server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        "https://as.example.com/token",
        None,
        Some(&rev_endpoint),
    );
    client
        .revoke_token(&meta, "some-token-to-revoke")
        .await
        .unwrap();

    let req = cap.lock().await.clone().unwrap();
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/revoke");
    let form = parse_form(&req.body);
    assert_eq!(
        form.get("token").map(String::as_str),
        Some("some-token-to-revoke")
    );
    assert_eq!(
        form.get("client_id").map(String::as_str),
        Some("https://app.example.com/metadata.json")
    );
}

/// Missing revocation endpoint in server metadata must error — we
/// shouldn't silently no-op when the caller asked to revoke.
#[tokio::test]
async fn revoke_without_endpoint_errors() {
    let client = real_client("https://app.example.com/metadata.json");
    let meta = server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        "https://as.example.com/token",
        None,
        None, // no revocation endpoint
    );
    let err = client.revoke_token(&meta, "tok").await.unwrap_err();
    assert!(matches!(err, OAuthError::MissingField(_)));
}

/// `OAuthSession::refresh` must wire a fresh TokenSet into the session's
/// mutex and make it visible on the next `session.token_set()` read.
#[tokio::test]
async fn session_refresh_updates_token_set_in_place() {
    let (token_base, _cap) = spawn_oneshot(Reply::json(
        200,
        br#"{
          "access_token":"at-fresh",
          "token_type":"DPoP",
          "refresh_token":"rt-fresh",
          "expires_in":3600,
          "scope":"atproto",
          "sub":"did:plc:abc"
        }"#
        .to_vec(),
    ))
    .await;
    let token_endpoint = format!("{token_base}/token");

    let client = real_client("https://app.example.com/metadata.json");
    let meta = server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        &token_endpoint,
        None,
        None,
    );
    let dpop = DpopKey::generate().unwrap();
    let current = TokenSet {
        issuer: "https://as.example.com".to_string(),
        sub: "did:plc:abc".to_string(),
        scope: "atproto".to_string(),
        access_token: "at-old".to_string(),
        refresh_token: Some("rt-old".to_string()),
        token_type: "DPoP".to_string(),
        expires_at: None,
        aud: None,
    };
    let session = OAuthSession::new(current, dpop, DpopNonceCache::new());

    assert_eq!(session.token_set().access_token, "at-old");
    session.refresh(&client, &meta).await.unwrap();
    assert_eq!(session.token_set().access_token, "at-fresh");
    assert_eq!(
        session.token_set().refresh_token.as_deref(),
        Some("rt-fresh")
    );
}

/// Concurrent `refresh()` calls share a single `/token` round-trip via
/// the session's internal refresh lock. We prove this with a one-shot
/// mock that only serves the first request — if the lock works, nine
/// of ten concurrent refreshes short-circuit on the rotated-token
/// check and never touch the network.
#[tokio::test]
async fn session_refresh_dedupes_concurrent_callers() {
    let (token_base, _cap) = spawn_oneshot(Reply::json(
        200,
        br#"{
          "access_token":"at-fresh",
          "token_type":"DPoP",
          "refresh_token":"rt-fresh",
          "expires_in":3600,
          "scope":"atproto",
          "sub":"did:plc:abc"
        }"#
        .to_vec(),
    ))
    .await;
    let token_endpoint = format!("{token_base}/token");

    let client = std::sync::Arc::new(real_client("https://app.example.com/metadata.json"));
    let meta = std::sync::Arc::new(server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        &token_endpoint,
        None,
        None,
    ));
    let dpop = DpopKey::generate().unwrap();
    let current = TokenSet {
        issuer: "https://as.example.com".to_string(),
        sub: "did:plc:abc".to_string(),
        scope: "atproto".to_string(),
        access_token: "at-old".to_string(),
        refresh_token: Some("rt-old".to_string()),
        token_type: "DPoP".to_string(),
        expires_at: None,
        aud: None,
    };
    let session = std::sync::Arc::new(OAuthSession::new(current, dpop, DpopNonceCache::new()));

    let mut handles = Vec::new();
    for _ in 0..10 {
        let s = session.clone();
        let c = client.clone();
        let m = meta.clone();
        handles.push(tokio::spawn(async move { s.refresh(&c, &m).await }));
    }

    for h in handles {
        h.await.unwrap().expect("refresh should not error");
    }

    assert_eq!(session.token_set().access_token, "at-fresh");
}

/// When the client is configured with a `ClientKeyset` and the AS
/// advertises a compatible `alg`, token-endpoint requests carry a
/// `client_assertion` + `client_assertion_type` in the form body.
#[tokio::test]
async fn refresh_sends_private_key_jwt_client_assertion() {
    use proto_blue_oauth::{ClientKey, ClientKeyset, DpopAlg};

    let (token_base, cap) = spawn_oneshot(Reply::json(
        200,
        br#"{
          "access_token":"at-fresh",
          "token_type":"DPoP",
          "refresh_token":"rt-fresh",
          "expires_in":3600,
          "scope":"atproto",
          "sub":"did:plc:abc"
        }"#
        .to_vec(),
    ))
    .await;
    let token_endpoint = format!("{token_base}/token");

    // Fresh ES256 key for the test — signing correctness is already
    // covered by unit tests; here we assert wire-level presence.
    use p256::ecdsa::SigningKey as P256SigningKey;
    let sk = P256SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let key = ClientKey {
        alg: DpopAlg::Es256,
        kid: "test-key".into(),
        d: sk.to_bytes().to_vec(),
    };

    let client = OAuthClient::new(client_metadata_with_id(
        "https://app.example.com/metadata.json",
    ))
    .with_keyset(ClientKeyset::new().with_key(key));

    let mut meta = server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        &token_endpoint,
        None,
        None,
    );
    meta.token_endpoint_auth_signing_alg_values_supported = Some(vec!["ES256".into()]);

    let dpop = DpopKey::generate().unwrap();
    let current = TokenSet {
        issuer: "https://as.example.com".to_string(),
        sub: "did:plc:abc".to_string(),
        scope: "atproto".to_string(),
        access_token: "at-old".to_string(),
        refresh_token: Some("rt-old".to_string()),
        token_type: "DPoP".to_string(),
        expires_at: None,
        aud: None,
    };
    client.refresh_token(&meta, &current, &dpop).await.unwrap();

    let captured = cap.lock().await.clone().expect("server saw a request");
    let form = parse_form(&captured.body);
    assert_eq!(
        form.get("client_assertion_type").map(String::as_str),
        Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    );
    let assertion = form
        .get("client_assertion")
        .expect("client_assertion must be present");
    // Three compact-JWS segments, not empty.
    assert_eq!(assertion.matches('.').count(), 2);
}

/// When the AS doesn't advertise any `token_endpoint_auth_signing_alg`
/// the client silently falls back to public-client auth (no
/// `client_assertion` even though a keyset is configured).
#[tokio::test]
async fn refresh_omits_client_assertion_when_as_does_not_advertise_alg() {
    use proto_blue_oauth::{ClientKey, ClientKeyset, DpopAlg};

    let (token_base, cap) = spawn_oneshot(Reply::json(
        200,
        br#"{
          "access_token":"at-fresh",
          "token_type":"DPoP",
          "refresh_token":"rt-fresh",
          "expires_in":3600,
          "scope":"atproto",
          "sub":"did:plc:abc"
        }"#
        .to_vec(),
    ))
    .await;
    let token_endpoint = format!("{token_base}/token");

    use p256::ecdsa::SigningKey as P256SigningKey;
    let sk = P256SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let key = ClientKey {
        alg: DpopAlg::Es256,
        kid: "test-key".into(),
        d: sk.to_bytes().to_vec(),
    };

    let client = OAuthClient::new(client_metadata_with_id(
        "https://app.example.com/metadata.json",
    ))
    .with_keyset(ClientKeyset::new().with_key(key));
    // Note: no `token_endpoint_auth_signing_alg_values_supported` set.
    let meta = server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        &token_endpoint,
        None,
        None,
    );

    let dpop = DpopKey::generate().unwrap();
    let current = TokenSet {
        issuer: "https://as.example.com".to_string(),
        sub: "did:plc:abc".to_string(),
        scope: "atproto".to_string(),
        access_token: "at-old".to_string(),
        refresh_token: Some("rt-old".to_string()),
        token_type: "DPoP".to_string(),
        expires_at: None,
        aud: None,
    };
    client.refresh_token(&meta, &current, &dpop).await.unwrap();

    let captured = cap.lock().await.clone().expect("server saw a request");
    let form = parse_form(&captured.body);
    assert!(!form.contains_key("client_assertion"));
    assert!(!form.contains_key("client_assertion_type"));
}

/// `callback_verified` must reject when the token response's `sub`
/// doesn't match the DID the client resolved up-front. Prevents a
/// compromised AS from silently swapping which user the client is
/// authenticated as.
#[tokio::test]
async fn callback_verified_rejects_sub_mismatch() {
    let (token_base, _cap) = spawn_oneshot(Reply::json(
        200,
        br#"{
          "access_token":"at-new",
          "token_type":"DPoP",
          "refresh_token":"rt-new",
          "expires_in":3600,
          "scope":"atproto",
          "sub":"did:plc:attacker"
        }"#
        .to_vec(),
    ))
    .await;
    let token_endpoint = format!("{token_base}/token");

    let client = real_client("https://app.example.com/metadata.json");
    let meta = server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        &token_endpoint,
        None,
        None,
    );
    let state = fresh_auth_state("https://as.example.com");

    let err = client
        .callback_verified(
            "code",
            None,
            Some("https://pds.example.com"),
            Some("did:plc:expected"),
            &state,
            &meta,
        )
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("did:plc:expected") && msg.contains("did:plc:attacker"),
        "error should name both DIDs: {msg}"
    );
}

/// `callback_verified` accepts matching `sub` and records `aud`.
#[tokio::test]
async fn callback_verified_accepts_sub_match_and_records_aud() {
    let (token_base, _cap) = spawn_oneshot(Reply::json(
        200,
        br#"{
          "access_token":"at-new",
          "token_type":"DPoP",
          "refresh_token":"rt-new",
          "expires_in":3600,
          "scope":"atproto",
          "sub":"did:plc:good"
        }"#
        .to_vec(),
    ))
    .await;
    let token_endpoint = format!("{token_base}/token");

    let client = real_client("https://app.example.com/metadata.json");
    let meta = server_metadata(
        "https://as.example.com",
        "https://as.example.com/authorize",
        &token_endpoint,
        None,
        None,
    );
    let state = fresh_auth_state("https://as.example.com");

    let ts = client
        .callback_verified(
            "code",
            None,
            Some("https://pds.example.com"),
            Some("did:plc:good"),
            &state,
            &meta,
        )
        .await
        .unwrap();
    assert_eq!(ts.sub, "did:plc:good");
    assert_eq!(ts.aud.as_deref(), Some("https://pds.example.com"));
}
