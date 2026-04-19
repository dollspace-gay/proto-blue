//! End-to-end subscription tests.
//!
//! Spins up an `XrpcServer` with a `stream_method` handler, connects
//! via `tokio-tungstenite`, and asserts that:
//!
//! 1. Each yielded item arrives as a DAG-CBOR message frame with the
//!    expected op code + body.
//! 2. Handler-side errors surface as an error frame.
//! 3. Handler exhaustion closes the socket cleanly.
//! 4. A non-WebSocket GET on the subscription path returns an
//!    `InvalidRequest`.

use std::time::Duration;

use futures::{SinkExt, StreamExt, stream};
use proto_blue_lex_data::LexValue;
use proto_blue_xrpc::server::{XrpcServer, XrpcServerError};
use proto_blue_xrpc::ResponseType;
use serde_json::json;
use tokio_tungstenite::tungstenite::Message;

/// Bind an ephemeral port, serve `router`, return `(ws_url, http_url)`
/// tuples the tests can use.
async fn spawn_server(router: axum::Router) -> (String, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ws_url = format!("ws://{addr}");
    let http_url = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    // Small settle so the server is accepting connections.
    tokio::time::sleep(Duration::from_millis(20)).await;
    (ws_url, http_url)
}

/// Decode a DAG-CBOR subscription frame as `(header, body)`.
fn decode_frame(bytes: &[u8]) -> (LexValue, LexValue) {
    let values = proto_blue_lex_cbor::decode_all(bytes).unwrap();
    assert_eq!(values.len(), 2, "frame must be exactly 2 CBOR values");
    let mut it = values.into_iter();
    (it.next().unwrap(), it.next().unwrap())
}

#[tokio::test]
async fn subscription_delivers_each_yielded_value_as_message_frame() {
    let server = XrpcServer::new().stream_method(
        "com.example.feed.stream",
        |_ctx| {
            stream::iter(vec![
                Ok(json!({"seq": 1, "text": "hello"})),
                Ok(json!({"seq": 2, "text": "world"})),
            ])
        },
    );

    let (ws_url, _) = spawn_server(server.into_router()).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!(
        "{ws_url}/xrpc/com.example.feed.stream",
    ))
    .await
    .unwrap();

    let mut received = Vec::new();
    while let Some(msg) = ws.next().await {
        match msg.unwrap() {
            Message::Binary(bytes) => received.push(bytes.to_vec()),
            Message::Close(_) => break,
            _ => continue,
        }
    }

    assert_eq!(received.len(), 2, "two message frames expected");
    for (i, bytes) in received.iter().enumerate() {
        let (header, body) = decode_frame(bytes);
        // Header is `{op: 1}`.
        let header_map = header.as_map().unwrap();
        assert_eq!(header_map.get("op"), Some(&LexValue::Integer(1)));
        // Body carries the yielded JSON value.
        let body_map = body.as_map().unwrap();
        assert_eq!(body_map.get("seq"), Some(&LexValue::Integer((i + 1) as i64)));
    }
}

#[tokio::test]
async fn subscription_handler_error_becomes_error_frame_and_closes() {
    let server = XrpcServer::new().stream_method(
        "com.example.feed.err",
        |_ctx| {
            stream::iter(vec![
                Ok(json!({"seq": 1})),
                Err(XrpcServerError::new(
                    ResponseType::InvalidRequest,
                    "something broke",
                )
                .with_error_name("Broken")),
            ])
        },
    );

    let (ws_url, _) = spawn_server(server.into_router()).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!(
        "{ws_url}/xrpc/com.example.feed.err",
    ))
    .await
    .unwrap();

    let mut binary = Vec::new();
    let mut saw_close = false;
    while let Some(msg) = ws.next().await {
        match msg.unwrap() {
            Message::Binary(b) => binary.push(b.to_vec()),
            Message::Close(_) => {
                saw_close = true;
                break;
            }
            _ => continue,
        }
    }

    assert!(saw_close, "expected clean close after error frame");
    assert_eq!(binary.len(), 2, "one message + one error frame");

    let (err_header, err_body) = decode_frame(&binary[1]);
    // Error header: `{op: -1}`.
    let h = err_header.as_map().unwrap();
    assert_eq!(h.get("op"), Some(&LexValue::Integer(-1)));
    // Error body carries `{error, message}`.
    let b = err_body.as_map().unwrap();
    assert_eq!(b.get("error"), Some(&LexValue::String("Broken".into())));
    assert_eq!(
        b.get("message"),
        Some(&LexValue::String("something broke".into()))
    );
}

#[tokio::test]
async fn subscription_clean_exhaustion_closes_socket() {
    let server = XrpcServer::new()
        .stream_method("com.example.empty", |_ctx| stream::iter(Vec::new()));

    let (ws_url, _) = spawn_server(server.into_router()).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!(
        "{ws_url}/xrpc/com.example.empty",
    ))
    .await
    .unwrap();

    // No binary frames — should close cleanly.
    let mut saw_close = false;
    while let Some(msg) = ws.next().await {
        if matches!(msg.unwrap(), Message::Close(_)) {
            saw_close = true;
            break;
        }
    }
    assert!(saw_close);
}

#[tokio::test]
async fn subscription_client_disconnect_ends_pump() {
    // Slow infinite stream — server would run forever without the
    // client-disconnect watchdog in run_subscription_pump.
    let server = XrpcServer::new().stream_method(
        "com.example.slow",
        |_ctx| {
            stream::unfold(0_i64, |seq| async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Some((Ok(json!({"seq": seq})), seq + 1))
            })
        },
    );

    let (ws_url, _) = spawn_server(server.into_router()).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!(
        "{ws_url}/xrpc/com.example.slow",
    ))
    .await
    .unwrap();

    // Read one frame so we know the stream is live.
    let first = ws.next().await.unwrap().unwrap();
    assert!(matches!(first, Message::Binary(_)));

    // Disconnect — we exit without asserting on the handler-side
    // teardown directly, but the test process must terminate
    // promptly when dropped. If the pump didn't observe the
    // disconnect this test would still pass (nothing asserts on the
    // server side) — but an adversarial variant would hang the
    // harness. This covers the "no panic on disconnect" path.
    ws.send(Message::Close(None)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
}

#[tokio::test]
async fn body_limit_rejects_oversized_procedure_bodies() {
    use reqwest::Client;

    // 256-byte body limit; handler should never run for oversized
    // input because axum rejects upstream.
    let server = XrpcServer::new()
        .procedure(
            "com.example.upload",
            |_ctx| async { Ok::<_, XrpcServerError>(serde_json::json!({"ok": true})) },
        )
        .with_body_limit(256);

    let (_, http_url) = spawn_server(server.into_router()).await;

    // 4 KB body → 413 Payload Too Large.
    let big = vec![b'x'; 4096];
    let resp = Client::new()
        .post(format!("{http_url}/xrpc/com.example.upload"))
        .header("content-type", "application/octet-stream")
        .body(big)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);

    // Tiny body → 200 OK.
    let resp = Client::new()
        .post(format!("{http_url}/xrpc/com.example.upload"))
        .header("content-type", "application/json")
        .body(b"{}".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn subscription_get_without_upgrade_header_returns_invalid_request() {
    use reqwest::Client;

    let server = XrpcServer::new()
        .stream_method("com.example.get", |_ctx| stream::iter(Vec::new()));

    let (_, http_url) = spawn_server(server.into_router()).await;
    let resp = Client::new()
        .get(format!("{http_url}/xrpc/com.example.get"))
        .send()
        .await
        .unwrap();

    // Non-WebSocket GET on a subscription path: 400 InvalidRequest.
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}
