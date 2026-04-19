//! Integration test for `proto_blue_oauth::resolve_input` — the
//! handle/DID/PDS-URL → (pds, AS metadata) orchestration.
//!
//! Only compiled when `identity-resolver` is on. For CI coverage, run
//! `cargo test -p proto-blue-oauth --features identity-resolver`.
//!
//! This test file is intentionally self-contained — it does NOT pull
//! in `tests/common/mock_server.rs` because it needs a variant of the
//! sequence-reply server that owns an already-bound listener (so the
//! test can build reply bodies that reference the port). Keeping it
//! standalone also avoids importing the full common surface into a
//! second compilation unit, which surfaces helpers that happen not to
//! be referenced here as spurious dead-code warnings.

#![cfg(feature = "identity-resolver")]

use std::sync::Arc;

use proto_blue_identity::IdResolver;
use proto_blue_oauth::{OAuthClient, OAuthClientMetadata};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn client_metadata_with_id(client_id: &str) -> OAuthClientMetadata {
    OAuthClientMetadata {
        client_id: client_id.to_string(),
        redirect_uris: vec!["https://app.example.com/callback".into()],
        response_types: Some(vec!["code".into()]),
        grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
        scope: Some("atproto".into()),
        token_endpoint_auth_method: Some("none".into()),
        application_type: Some("web".into()),
        dpop_bound_access_tokens: Some(true),
        client_name: None,
        client_uri: None,
        logo_uri: None,
        token_endpoint_auth_signing_alg: None,
    }
}

/// PDS-URL input path: identity resolution is skipped, only
/// `discover_resource` + `discover_server` fire. Assert we get a
/// `ResolvedInput` with `did=None` and the AS metadata echoed back.
#[tokio::test]
async fn resolve_input_with_pds_url_skips_identity_and_returns_metadata() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let resource_body = format!(r#"{{"resource":"{base}","authorization_servers":["{base}"]}}"#);
    let server_body = format!(
        r#"{{"issuer":"{base}","authorization_endpoint":"{base}/authorize","token_endpoint":"{base}/token"}}"#
    );

    let _server = spawn_sequence_on_listener(
        listener,
        vec![
            (200, resource_body.into_bytes()),
            (200, server_body.into_bytes()),
        ],
    );

    let resolver = IdResolver::with_fetch_handler(
        Default::default(),
        None,
        Arc::new(proto_blue_common::fetch::ReqwestFetcher::new()),
    );
    let client = OAuthClient::new(client_metadata_with_id(
        "https://app.example.com/metadata.json",
    ));

    let got = proto_blue_oauth::resolve_input(&resolver, &client, &base)
        .await
        .unwrap();

    assert!(got.did.is_none(), "PDS-URL input: did should be None");
    assert_eq!(got.pds_url, base);
    assert_eq!(got.server_metadata.issuer, base);
    assert_eq!(got.server_metadata.token_endpoint, format!("{base}/token"));
}

/// When the PDS's resource metadata advertises **no** authorization
/// servers, `resolve_input` must surface a clear error rather than
/// silently falling back.
#[tokio::test]
async fn resolve_input_errors_when_resource_metadata_has_no_as() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let resource_body = format!(r#"{{"resource":"{base}","authorization_servers":[]}}"#);

    let _server = spawn_sequence_on_listener(listener, vec![(200, resource_body.into_bytes())]);

    let resolver = IdResolver::with_fetch_handler(
        Default::default(),
        None,
        Arc::new(proto_blue_common::fetch::ReqwestFetcher::new()),
    );
    let client = OAuthClient::new(client_metadata_with_id(
        "https://app.example.com/metadata.json",
    ));

    let err = proto_blue_oauth::resolve_input(&resolver, &client, &base)
        .await
        .expect_err("expected resolve_input to fail on empty authorization_servers");
    let msg = err.to_string();
    // `discover_resource` rejects empty / wrong-length authorization
    // server lists before `resolve_input` even sees the metadata,
    // surfacing a message about the required count.
    assert!(
        msg.contains("authorization_server"),
        "error should mention authorization_server count: {msg}"
    );
}

/// The mock must receive requests in the documented order: first a
/// GET on `/.well-known/oauth-protected-resource`, then a GET on
/// `/.well-known/oauth-authorization-server`. We capture both
/// request paths and verify the ordering.
#[tokio::test]
async fn resolve_input_fetches_resource_metadata_then_server_metadata() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let resource_body = format!(r#"{{"resource":"{base}","authorization_servers":["{base}"]}}"#);
    let server_body = format!(
        r#"{{"issuer":"{base}","authorization_endpoint":"{base}/authorize","token_endpoint":"{base}/token"}}"#
    );

    let captured: Arc<tokio::sync::Mutex<Vec<String>>> = Arc::new(tokio::sync::Mutex::new(vec![]));
    let cap_clone = captured.clone();
    let _server = spawn_sequence_on_listener_capturing(
        listener,
        vec![
            (200, resource_body.into_bytes()),
            (200, server_body.into_bytes()),
        ],
        cap_clone,
    );

    let resolver = IdResolver::with_fetch_handler(
        Default::default(),
        None,
        Arc::new(proto_blue_common::fetch::ReqwestFetcher::new()),
    );
    let client = OAuthClient::new(client_metadata_with_id(
        "https://app.example.com/metadata.json",
    ));
    proto_blue_oauth::resolve_input(&resolver, &client, &base)
        .await
        .unwrap();

    let paths = captured.lock().await.clone();
    assert_eq!(paths.len(), 2, "expected two requests, saw {paths:?}");
    assert_eq!(paths[0], "/.well-known/oauth-protected-resource");
    assert_eq!(paths[1], "/.well-known/oauth-authorization-server");
}

/// Serve `replies` in order over `listener`. Each reply is
/// `(status, body)`; `Content-Type: application/json` is assumed.
/// Returning the `JoinHandle` lets the caller keep the server alive
/// for the duration of the test.
fn spawn_sequence_on_listener(
    listener: tokio::net::TcpListener,
    replies: Vec<(u16, Vec<u8>)>,
) -> tokio::task::JoinHandle<()> {
    spawn_sequence_on_listener_capturing(
        listener,
        replies,
        Arc::new(tokio::sync::Mutex::new(vec![])),
    )
}

/// Same as `spawn_sequence_on_listener` but records each incoming
/// request path into `captured` so the test can assert on the
/// request ordering.
fn spawn_sequence_on_listener_capturing(
    listener: tokio::net::TcpListener,
    replies: Vec<(u16, Vec<u8>)>,
    captured: Arc<tokio::sync::Mutex<Vec<String>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for (status, body) in replies {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                let n = match socket.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // Capture the request path (first whitespace-delimited
            // token after the method on the request line).
            if let Some(req_line) = std::str::from_utf8(&buf)
                .ok()
                .and_then(|s| s.lines().next())
            {
                if let Some(path) = req_line.split_whitespace().nth(1) {
                    captured.lock().await.push(path.to_string());
                }
            }

            let head = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(head.as_bytes()).await;
            let _ = socket.write_all(&body).await;
            let _ = socket.flush().await;
        }
    })
}
