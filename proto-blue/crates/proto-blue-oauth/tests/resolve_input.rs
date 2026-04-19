//! Integration test for `proto_blue_oauth::resolve_input` — the
//! handle/DID/PDS-URL → (pds, AS metadata) orchestration.
//!
//! Only compiled when `identity-resolver` is on. For CI coverage, run
//! `cargo test -p proto-blue-oauth --features identity-resolver`.

#![cfg(feature = "identity-resolver")]

mod common;

use common::mock_server::Reply;
use proto_blue_identity::IdResolver;
use proto_blue_oauth::{OAuthClient, OAuthClientMetadata};

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
        client_name: None,
        client_uri: None,
        logo_uri: None,
    }
}

/// PDS-URL input path: identity resolution is skipped, only
/// `discover_resource` + `discover_server` fire. Assert we get a
/// `ResolvedInput` with `did=None` and the AS metadata echoed back.
#[tokio::test]
async fn resolve_input_with_pds_url_skips_identity_and_returns_metadata() {
    // The mock server needs to reply to two requests in order:
    //   1. GET /.well-known/oauth-protected-resource  →  {authorization_servers: ["<base>"]}
    //   2. GET /.well-known/oauth-authorization-server → server metadata
    // We bind the listener up front so we can read its port, then
    // hand the bound listener into the spawned task along with the
    // self-referential reply bodies.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let resource_body = format!(r#"{{"resource":"{base}","authorization_servers":["{base}"]}}"#);
    let server_body = format!(
        r#"{{
          "issuer":"{base}",
          "authorization_endpoint":"{base}/authorize",
          "token_endpoint":"{base}/token"
        }}"#
    );
    let replies = vec![
        Reply::json(200, resource_body.into_bytes()),
        Reply::json(200, server_body.into_bytes()),
    ];

    let _server = spawn_sequence_on_listener(listener, replies);

    let resolver = IdResolver::with_fetch_handler(
        Default::default(),
        None,
        std::sync::Arc::new(proto_blue_common::fetch::ReqwestFetcher::new()),
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

/// Drive `replies` out over an already-bound listener. Returning the
/// `JoinHandle` lets the caller extend its lifetime through the end
/// of the test (`drop`ping it early would cancel the server).
fn spawn_sequence_on_listener(
    listener: tokio::net::TcpListener,
    replies: Vec<Reply>,
) -> tokio::task::JoinHandle<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::spawn(async move {
        for reply in replies {
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
            let ct = reply
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
                .map_or_else(|| "application/octet-stream".into(), |(_, v)| v.clone());
            let head = format!(
                "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n",
                reply.status,
                ct,
                reply.body.len()
            );
            let _ = socket.write_all(head.as_bytes()).await;
            let _ = socket.write_all(&reply.body).await;
            let _ = socket.flush().await;
        }
    })
}
